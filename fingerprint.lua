require "apache2"

-- Konfigurasi
local MAX_REQUESTS = 3    -- Maksimal request per kombinasi headers
local BLOCK_TIME = 60     -- Waktu blokir dalam detik
local BOT_THRESHOLD = 70  -- Threshold skor bot (0-100, semakin kecil = semakin mencurigakan)
local STRICT_MODE = true  -- Mode strict untuk bot detection
local LOG_FILE = "/var/log/apache2/lua/apache_antibrute.log"
local DATA_FILE = "/var/log/apache2/lua/apache_antibrute_data.txt"
local SCORE_FILE = "/var/log/apache2/lua/apache_antibrute_scores.txt"

-- Database fingerprint bot yang dikenal
local BOT_SIGNATURES = {
    user_agents = {
        ["python-requests"] = true,
        ["curl/"] = true,
        ["wget/"] = true,
        ["java/"] = true,
        ["go-http-client"] = true,
        ["php/"] = true,
        ["libwww-perl"] = true,
        ["httpclient"] = true,
        ["okhttp"] = true,
        ["axios/"] = true,
        ["node-fetch"] = true,
        ["bot"] = true,
        ["crawler"] = true,
        ["spider"] = true,
        ["scraper"] = true,
        ["scanner"] = true,
        ["headless"] = true,
        ["phantom"] = true,
        ["selenium"] = true,
        ["puppeteer"] = true,
        ["playwright"] = true
    },
    suspicious_patterns = {
        "^Mozilla/4%.0$",
        "^Mozilla/5%.0$",
        "^User%-Agent:$",
        "^$",
        "test",
        "null",
        "undefined"
    }
}

-- Fungsi utilitas untuk log
function log_message(msg)
    local f, err = io.open(LOG_FILE, "a")
    if f then
        f:write(os.date("%Y-%m-%d %H:%M:%S") .. " - " .. msg .. "\n")
        f:close()
        return true
    end
    return false
end

-- Fungsi untuk membersihkan string header
function clean_header_value(value)
    if not value or value == "" then
        return "empty"
    end
    value = value:gsub(":", "_")
    value = value:gsub("|", "_")
    value = value:gsub("\n", " ")
    value = value:gsub("\r", " ")
    value = value:gsub("\t", " ")
    if #value > 200 then
        value = value:sub(1, 200)
    end
    return value
end

-- Fungsi untuk menghitung entropy dari string
function calculate_entropy(str)
    if not str or #str == 0 then return 0 end
    
    local freq = {}
    for i = 1, #str do
        local char = str:sub(i, i)
        freq[char] = (freq[char] or 0) + 1
    end
    
    local entropy = 0
    local len = #str
    for char, count in pairs(freq) do
        local prob = count / len
        entropy = entropy - (prob * math.log(prob) / math.log(2))
    end
    
    return entropy
end

-- Fungsi untuk menghitung skor bot berdasarkan fingerprint
function calculate_bot_score(fingerprint)
    local score = 100 -- Mulai dengan skor maksimal (human-like)
    
    local ip_address = fingerprint.ip or ""
    local user_agent = fingerprint.user_agent or ""
    local accept_language = fingerprint.accept_language or ""
    local accept_encoding = fingerprint.accept_encoding or ""
    local accept = fingerprint.accept or ""
    local referer = fingerprint.referer or ""
    local sec_fetch_headers = fingerprint.sec_fetch_site .. fingerprint.sec_fetch_mode .. fingerprint.sec_fetch_dest
    
    -- 1. Analisis User-Agent (25 poin)
    if user_agent == "empty" or user_agent == "" then
        score = score - 25
    else
        -- Cek bot signatures
        local ua_lower = user_agent:lower()
        for bot_ua, _ in pairs(BOT_SIGNATURES.user_agents) do
            if ua_lower:find(bot_ua:lower(), 1, true) then
                score = score - 20
                break
            end
        end
        
        -- Cek pola mencurigakan
        for _, pattern in ipairs(BOT_SIGNATURES.suspicious_patterns) do
            if user_agent:match(pattern) then
                score = score - 15
                break
            end
        end
        
        -- Cek panjang user agent (terlalu pendek = mencurigakan)
        if #user_agent < 20 then
            score = score - 10
        end
        
        -- Cek entropy user agent
        local ua_entropy = calculate_entropy(user_agent)
        if ua_entropy < 3.5 then -- Entropy rendah = pola berulang
            score = score - 8
        end
    end
    
    -- 2. Analisis Accept Headers (20 poin)
    if accept == "empty" or accept == "*/*" then
        score = score - 10
    end
    if accept_encoding == "empty" then
        score = score - 10
    end
    
    -- 3. Analisis Accept-Language (15 poin)
    if accept_language == "empty" then
        score = score - 15
    elseif not accept_language:find(",") and #accept_language < 5 then
        -- Bahasa tunggal tanpa quality values = mencurigakan
        score = score - 8
    end
    
    -- 4. Analisis Sec-Fetch Headers (15 poin)
    if sec_fetch_headers == "emptyemptyempty" then
        score = score - 10
    elseif fingerprint.sec_fetch_site == "none" and fingerprint.sec_fetch_mode == "navigate" then
        -- Pattern normal untuk direct navigation
        score = score + 5
    end
    
    -- 5. Analisis Referer (10 poin)
    if referer == "empty" then
        score = score - 5
    elseif referer:find("http") and not referer:find(ip_address) then
        -- Ada referer dari domain lain (normal untuk web browsing)
        score = score + 3
    end
    
    -- 6. Analisis DNT Header (5 poin)
    if fingerprint.dnt ~= "empty" then
        score = score + 2 -- DNT header biasanya dari browser real
    end
    
    -- 7. Konsistensi header kombinasi (10 poin)
    local header_count = 0
    if user_agent ~= "empty" then header_count = header_count + 1 end
    if accept ~= "empty" then header_count = header_count + 1 end
    if accept_language ~= "empty" then header_count = header_count + 1 end
    if accept_encoding ~= "empty" then header_count = header_count + 1 end
    if referer ~= "empty" then header_count = header_count + 1 end
    
    if header_count < 3 then
        score = score - 10
    elseif header_count >= 5 then
        score = score + 5
    end
    
    -- Normalisasi skor (0-100)
    if score < 0 then score = 0 end
    if score > 100 then score = 100 end
    
    return math.floor(score)
end

-- Fungsi untuk menyimpan skor fingerprint
function save_fingerprint_score(client_key, score, fingerprint)
    local f, err = io.open(SCORE_FILE, "a")
    if f then
        local timestamp = os.time()
        local summary = string.format("IP:%s|UA:%s|Score:%d", 
            fingerprint.ip or "unknown", 
            (fingerprint.user_agent or "empty"):sub(1, 50), 
            score)
        f:write(string.format("%d|%d|%s\n", timestamp, score, summary))
        f:close()
    end
end

-- Fungsi untuk mengirim respons dengan detail skor
function send_blocked_response(r, ttl, score, reason)
    r.status = 429
    r.content_type = "text/html"
    r.headers_out["Retry-After"] = tostring(ttl or BLOCK_TIME)
    r.headers_out["X-Bot-Score"] = tostring(score)
    r.headers_out["X-Block-Reason"] = reason
    
    local custom_message = [[
    <!DOCTYPE html>
    <html>
    <head>
        <title>Access Blocked</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .error { color: #d9534f; margin-bottom: 20px; }
            .score { color: #f0ad4e; font-size: 18px; margin: 15px 0; }
            .reason { color: #5bc0de; margin: 15px 0; }
            .retry { margin-top: 20px; font-size: 16px; }
            .countdown { font-weight: bold; color: #5cb85c; }
        </style>
        <script>
            function updateCountdown() {
                var retryAfter = parseInt(document.getElementById('retry-after').textContent);
                if (retryAfter > 0) {
                    document.getElementById('retry-after').textContent = retryAfter - 1;
                    setTimeout(updateCountdown, 1000);
                } else {
                    document.getElementById('retry-message').innerHTML = '<strong>You can try again now!</strong>';
                }
            }
            window.onload = function() { updateCountdown(); }
        </script>
    </head>
    <body>
        <div class="container">
            <h1 class="error">🚫 Access Blocked</h1>
            <div class="score">Bot Detection Score: ]] .. score .. [[%</div>
            <div class="reason">Reason: ]] .. reason .. [[</div>
            <p>Your request has been blocked due to suspicious activity patterns.</p>
            <div class="retry" id="retry-message">
                <p>Please wait <span id="retry-after" class="countdown">]] .. (ttl or BLOCK_TIME) .. [[</span> seconds before trying again.</p>
            </div>
            <small style="color: #999; margin-top: 20px; display: block;">
                If you believe this is an error, please contact the administrator.
            </small>
        </div>
    </body>
    </html>
    ]]
    r:puts(custom_message)
    return apache2.DONE
end

-- Fungsi untuk membaca data dari file
function read_counter(client_key)
    local f, err = io.open(DATA_FILE, "r")
    if not f then
        return nil, 0
    end
    for line in f:lines() do
        local key, timestamp, count = line:match("^(.+)|(.+)|(.+)$")
        if key == client_key then
            f:close()
            return tonumber(timestamp), tonumber(count)
        end
    end
    f:close()
    return nil, 0
end

-- Fungsi untuk menulis data ke file
function write_counter(client_key, timestamp, count)
    local f, err = io.open(DATA_FILE, "r")
    local lines = {}
    if f then
        for line in f:lines() do
            local key = line:match("^(.+)|")
            if key ~= client_key then
                table.insert(lines, line)
            end
        end
        f:close()
    end
    table.insert(lines, string.format("%s|%d|%d", client_key, timestamp, count))
    f, err = io.open(DATA_FILE, "w")
    if f then
        for _, line in ipairs(lines) do
            f:write(line .. "\n")
        end
        f:close()
    end
end

-- Fungsi untuk membersihkan data expired
function cleanup_expired_data()
    local f, err = io.open(DATA_FILE, "r")
    if not f then return end
    
    local current_time = os.time()
    local lines = {}
    for line in f:lines() do
        local key, timestamp, count = line:match("^(.+)|(.+)|(.+)$")
        if timestamp and (current_time - tonumber(timestamp)) <= BLOCK_TIME then
            table.insert(lines, line)
        end
    end
    f:close()
    
    f, err = io.open(DATA_FILE, "w")
    if f then
        for _, line in ipairs(lines) do
            f:write(line .. "\n")
        end
        f:close()
    end
    
    -- Bersihkan score file juga
    f, err = io.open(SCORE_FILE, "r")
    if f then
        local score_lines = {}
        for line in f:lines() do
            local timestamp = line:match("^(%d+)|")
            if timestamp and (current_time - tonumber(timestamp)) <= (BLOCK_TIME * 24) then -- Keep scores for 24x longer
                table.insert(score_lines, line)
            end
        end
        f:close()
        
        f, err = io.open(SCORE_FILE, "w")
        if f then
            for _, line in ipairs(score_lines) do
                f:write(line .. "\n")
            end
            f:close()
        end
    end
end

-- Fungsi untuk mendapatkan nilai header
function get_header_value(r, header_name)
    if r.headers_in and r.headers_in[header_name] then
        return r.headers_in[header_name]
    end
    
    local env_header_name = "HTTP_" .. header_name:gsub("-", "_"):upper()
    if r.subprocess_env and r.subprocess_env[env_header_name] then
        return r.subprocess_env[env_header_name]
    end
    
    return nil
end

-- Fungsi utama untuk pengecekan akses
function check_access(r)
    -- Dapatkan IP address
    local ip_address = nil
    if r.useragent_ip then
        ip_address = r.useragent_ip
    end
    if not ip_address and r.headers_in then
        local headers = r.headers_in
        if headers["X-Forwarded-For"] then
            ip_address = headers["X-Forwarded-For"]:match("([^,]+)")
        elseif headers["X-Real-IP"] then
            ip_address = headers["X-Real-IP"]
        elseif headers["CF-Connecting-IP"] then
            ip_address = headers["CF-Connecting-IP"]
        end
    end
    if not ip_address and r.subprocess_env then
        ip_address = r.subprocess_env["REMOTE_ADDR"]
    end
    if not ip_address then
        return apache2.OK
    end

    -- Kumpulkan semua headers untuk fingerprinting
    local fingerprint = {
        ip = ip_address,
        user_agent = clean_header_value(get_header_value(r, "User-Agent") or "empty"),
        accept_language = clean_header_value(get_header_value(r, "Accept-Language") or "empty"),
        accept_encoding = clean_header_value(get_header_value(r, "Accept-Encoding") or "empty"),
        accept = clean_header_value(get_header_value(r, "Accept") or "empty"),
        dnt = clean_header_value(get_header_value(r, "DNT") or "empty"),
        sec_fetch_site = clean_header_value(get_header_value(r, "Sec-Fetch-Site") or "empty"),
        sec_fetch_mode = clean_header_value(get_header_value(r, "Sec-Fetch-Mode") or "empty"),
        sec_fetch_dest = clean_header_value(get_header_value(r, "Sec-Fetch-Dest") or "empty"),
        referer = clean_header_value(get_header_value(r, "Referer") or "empty")
    }

    -- Buat client key
    local client_key = string.format("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
        fingerprint.ip,
        fingerprint.user_agent,
        fingerprint.accept_language,
        fingerprint.accept_encoding,
        fingerprint.accept,
        fingerprint.dnt,
        fingerprint.sec_fetch_site,
        fingerprint.sec_fetch_mode,
        fingerprint.sec_fetch_dest,
        fingerprint.referer
    )

    -- Hitung skor bot
    local bot_score = calculate_bot_score(fingerprint)
    
    -- Bersihkan data expired secara berkala
    if math.random(20) == 1 then
        cleanup_expired_data()
    end

    local current_time = os.time()
    local last_time, count = read_counter(client_key)

    -- Reset hitungan jika sudah melewati BLOCK_TIME
    if last_time and (current_time - last_time) > BLOCK_TIME then
        count = 0
    end

    -- Simpan skor untuk analisis
    save_fingerprint_score(client_key, bot_score, fingerprint)

    -- Logika blocking berdasarkan skor dan jumlah request
    local should_block = false
    local block_reason = ""
    local ttl = BLOCK_TIME

    -- Cek berdasarkan skor bot
    if STRICT_MODE and bot_score <= BOT_THRESHOLD then
        should_block = true
        block_reason = "Bot/Suspicious Activity (Score: " .. bot_score .. "%)"
        -- Bot dengan skor rendah diblokir lebih lama
        if bot_score <= 10 then
            ttl = BLOCK_TIME * 3
        elseif bot_score <= 20 then
            ttl = BLOCK_TIME * 2
        end
    end

    -- Cek berdasarkan jumlah request (dengan adjustment berdasarkan skor)
    local adjusted_max_requests = MAX_REQUESTS
    if bot_score <= 50 then
        adjusted_max_requests = math.max(1, math.floor(MAX_REQUESTS * (bot_score / 100)))
    end

    if count >= adjusted_max_requests then
        should_block = true
        if block_reason == "" then
            block_reason = "Too Many Requests (Score: " .. bot_score .. "%, Limit: " .. adjusted_max_requests .. ")"
        end
        ttl = BLOCK_TIME - (current_time - (last_time or current_time))
        if ttl < 1 then ttl = BLOCK_TIME end
    end

    if should_block then
        log_message(string.format("BLOCKED - IP: %s, Score: %d%%, Count: %d/%d, Reason: %s, UA: %s", 
            ip_address, bot_score, count, adjusted_max_requests, block_reason, 
            fingerprint.user_agent:sub(1, 50)))
        return send_blocked_response(r, ttl, bot_score, block_reason)
    end

    -- Update hitungan dan izinkan akses
    write_counter(client_key, current_time, count + 1)
    log_message(string.format("ALLOWED - IP: %s, Score: %d%%, Count: %d/%d, UA: %s", 
        ip_address, bot_score, count + 1, adjusted_max_requests, fingerprint.user_agent:sub(1, 50)))
    
    return apache2.OK
end