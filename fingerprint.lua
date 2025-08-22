require "apache2"

-- Konfigurasi
local MAX_REQUESTS = 3    -- Maksimal request per kombinasi headers
local BLOCK_TIME = 60     -- Waktu blokir dalam detik
local BOT_THRESHOLD = 70  -- Threshold skor bot (0-100, semakin kecil = semakin mencurigakan)
local STRICT_MODE = true  -- Mode strict untuk bot detection

-- Whitelist IP addresses - IP yang dikecualikan dari pemeriksaan
local WHITELIST_IPS = {
    -- ["127.0.0.1"] = true,        -- localhost
    -- ["::1"] = true,              -- IPv6 localhost
    -- ["10.0.0.1"] = true,         -- contoh: gateway internal
    -- ["192.168.1.1"] = true,      -- contoh: router internal
    -- Tambahkan IP yang ingin di-whitelist di sini
    -- ["203.0.113.123"] = true, -- contoh: IP kantor
    -- ["198.51.100.0/24"] = true, -- contoh: range IP (akan diimplementasi terpisah)
}

-- Whitelist IP ranges (CIDR notation support)
local WHITELIST_RANGES = {
    -- "127.0.0.0/8",      -- localhost range
    -- "10.0.0.0/8",       -- private network
    -- "192.168.0.0/16",   -- private network
    -- "172.16.0.0/12",    -- private network
    -- Tambahkan range IP yang ingin di-whitelist di sini
    -- "203.0.113.0/24", -- contoh: range kantor
}

-- File logs yang dipisah berdasarkan kategori
local LOG_FILES = {
    main = "/var/log/apache2/lua/apache_antibrute.log",
    access = "/var/log/apache2/lua/access_detailed.log",
    blocked = "/var/log/apache2/lua/blocked_requests.log",
    user_activity = "/var/log/apache2/lua/user_activity.log",
    request_body = "/var/log/apache2/lua/request_body.log"
}

local DATA_FILE = "/var/log/apache2/lua/apache_antibrute_data.txt"
local SCORE_FILE = "/var/log/apache2/lua/apache_antibrute_scores.txt"
local WHITELIST_FILE = "/etc/apache2/lua/whitelist_ips.txt"

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

-- Fungsi utilitas untuk log dengan kategori
function log_message(msg, log_type)
    log_type = log_type or "main"
    local log_file = LOG_FILES[log_type] or LOG_FILES.main
    
    local f, err = io.open(log_file, "a")
    if f then
        f:write(os.date("%Y-%m-%d %H:%M:%S") .. " - " .. msg .. "\n")
        f:close()
        return true
    end
    return false
end

-- Cache untuk whitelist yang dimuat dari file
local DYNAMIC_WHITELIST_IPS = {}
local DYNAMIC_WHITELIST_RANGES = {}
local WHITELIST_LAST_LOADED = 0
local WHITELIST_RELOAD_INTERVAL = 300 -- Reload setiap 5 menit

-- Skip Request
function should_skip_request(r)
    -- 1. Skip untuk request dengan cookie session (umum untuk semua aplikasi web)
    local cookie = r.headers_in and r.headers_in["Cookie"] or ""
    if cookie:match("session") or cookie:match("SESSION") or 
       cookie:match("token") or cookie:match("TOKEN") or
       cookie:match("csrf") or cookie:match("CSRF") or
       cookie:match("auth") or cookie:match("AUTH") then
        return true, "Session cookie detected"
    end
    
    -- 2. Skip untuk request AJAX (umum untuk aplikasi web modern)
    if r.headers_in and r.headers_in["X-Requested-With"] == "XMLHttpRequest" then
        return true, "AJAX request detected"
    end
    
    -- 3. Skip untuk header keamanan umum
    local security_headers = {
        ["X-CSRF-TOKEN"] = true,
        ["X-XSRF-TOKEN"] = true,
        ["X-Requested-With"] = true,
        ["X-API-KEY"] = true,
        ["X-Auth-Token"] = true,
        ["X-Access-Token"] = true,
        ["Authorization"] = true,
        ["Proxy-Authorization"] = true,
        ["WWW-Authenticate"] = true,
        ["Cookie"] = true  -- Skip semua request yang memiliki cookie
    }
    
    if r.headers_in then
        for header, _ in pairs(security_headers) do
            if r.headers_in[header] then
                return true, "Security header detected: " .. header
            end
        end
    end
    
    -- 4. Skip untuk header framework modern
    local framework_headers = {
        ["X-Livewire"] = true,
        ["X-Inertia"] = true,
        ["X-Vue-Component"] = true,
        ["X-React-Component"] = true,
        ["X-Angular-Component"] = true,
        ["X-Nextjs-Data"] = true,
        ["X-Nuxt-Data"] = true,
        ["X-WordPress"] = true,
        ["X-Joomla"] = true,
        ["X-Drupal"] = true
    }
    
    if r.headers_in then
        for header, _ in pairs(framework_headers) do
            if r.headers_in[header] then
                return true, "Framework header detected: " .. header
            end
        end
    end
    
    -- 5. Skip untuk file statis (umum untuk semua website)
    local static_extensions = {
        "%.css$", "%.js$", "%.png$", "%.jpg$", "%.jpeg$", "%.gif$", 
        "%.ico$", "%.svg$", "%.woff$", "%.woff2$", "%.ttf$", "%.eot$", 
        "%.otf$", "%.mp4$", "%.webm$", "%.mp3$", "%.wav$", "%.pdf$",
        "%.doc$", "%.docx$", "%.xls$", "%.xlsx$", "%.ppt$", "%.pptx$",
        "%.zip$", "%.rar$", "%.tar$", "%.gz$", "%.7z$", "%.dmg$",
        "%.exe$", "%.msi$", "%.deb$", "%.rpm$", "%.apk$", "%.ipa$"
    }
    
    local uri = r.uri or ""
    for _, pattern in ipairs(static_extensions) do
        if uri:match(pattern) then
            return true, "Static file detected: " .. uri
        end
    end
    
    -- 6. Skip untuk route umum yang tidak perlu pemeriksaan
    local skip_routes = {
        "^/robots%.txt$", "^/sitemap%.xml$", "^/favicon%.ico$",
        "^/apple%-touch%-icon", "^/manifest%.json$",
        "^/health$", "^/ping$", "^/status$",
        "^/metrics$", "^/monitoring$", "^/uptime$"
    }
    
    for _, pattern in ipairs(skip_routes) do
        if uri:match(pattern) then
            return true, "Common route detected: " .. uri
        end
    end
    
    -- 7. Skip untuk method HTTP yang tidak perlu pemeriksaan
    local skip_methods = {
        "OPTIONS", "HEAD", "TRACE"
    }
    
    local method = r.method or ""
    for _, skip_method in ipairs(skip_methods) do
        if method == skip_method then
            return true, "Skip method: " .. method
        end
    end
    
    -- 8. Skip untuk User-Agent tertentu (bot yang aman)
    local safe_user_agents = {
        "googlebot", "bingbot", "slurp", "duckduckbot", 
        "baiduspider", "yandexbot", "facebookexternalhit",
        "twitterbot", "linkedinbot", "whatsapp", "telegram",
        "slackbot", "discordbot", "skypeuripreview",
        "wordpress", "jetpack", "woocommerce"
    }
    
    local user_agent = r.headers_in and r.headers_in["User-Agent"] or ""
    user_agent = user_agent:lower()
    
    for _, bot in ipairs(safe_user_agents) do
        if user_agent:match(bot) then
            return true, "Safe bot detected: " .. bot
        end
    end
    
    return false, ""
end

-- Fungsi untuk memuat whitelist dari file
function load_whitelist_from_file()
    local current_time = os.time()
    
    -- Reload hanya jika sudah melewati interval atau belum pernah dimuat
    if (current_time - WHITELIST_LAST_LOADED) < WHITELIST_RELOAD_INTERVAL and WHITELIST_LAST_LOADED > 0 then
        return
    end
    
    WHITELIST_LAST_LOADED = current_time
    
    -- Reset cache
    DYNAMIC_WHITELIST_IPS = {}
    DYNAMIC_WHITELIST_RANGES = {}
    
    local f, err = io.open(WHITELIST_FILE, "r")
    if not f then
        -- Jika file tidak ada, buat file contoh
        create_sample_whitelist_file()
        return
    end
    
    for line in f:lines() do
        line = line:match("^%s*(.-)%s*$") -- trim whitespace
        if line and line ~= "" and not line:match("^#") then -- skip empty lines dan comments
            if line:match("/") then
                -- CIDR range
                table.insert(DYNAMIC_WHITELIST_RANGES, line)
            else
                -- Single IP
                DYNAMIC_WHITELIST_IPS[line] = true
            end
        end
    end
    f:close()
    
    log_message(string.format("Whitelist reloaded: %d IPs, %d ranges", 
        count_table_keys(DYNAMIC_WHITELIST_IPS), #DYNAMIC_WHITELIST_RANGES), "main")
end

-- Fungsi untuk membuat file whitelist contoh
function create_sample_whitelist_file()
    local f, err = io.open(WHITELIST_FILE, "w")
    if f then
        f:write("# Apache Anti-Brute Force - Whitelist IP Configuration\n")
        f:write("# Format: satu IP atau CIDR range per baris\n")
        f:write("# Baris yang diawali dengan # adalah komentar\n")
        f:write("#\n")
        f:write("# Contoh single IP:\n")
        f:write("# 203.0.113.123\n")
        f:write("# 198.51.100.456\n")
        f:write("#\n")
        f:write("# Contoh CIDR range:\n")
        f:write("# 203.0.113.0/24\n")
        f:write("# 10.1.0.0/16\n")
        f:write("#\n")
        f:write("# Default localhost entries (aktif):\n")
        f:write("127.0.0.1\n")
        f:write("::1\n")
        f:write("127.0.0.0/8\n")
        f:close()
        
        log_message("Created sample whitelist file: " .. WHITELIST_FILE, "main")
    end
end

-- Fungsi untuk menghitung jumlah keys dalam table
function count_table_keys(t)
    local count = 0
    for _ in pairs(t) do count = count + 1 end
    return count
end
function ip_to_number(ip)
    if not ip or ip == "" then return nil end
    
    local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if a and b and c and d then
        return tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
    end
    return nil
end

-- Fungsi untuk parse CIDR range
function parse_cidr(cidr)
    if not cidr or cidr == "" then return nil, nil end
    
    local ip, prefix = cidr:match("([%d%.]+)/(%d+)")
    if not ip or not prefix then return nil, nil end
    
    local ip_num = ip_to_number(ip)
    if not ip_num then return nil, nil end
    
    local prefix_num = tonumber(prefix)
    if not prefix_num or prefix_num < 0 or prefix_num > 32 then return nil, nil end
    
    local mask = bit32 and (0xFFFFFFFF - (2^(32 - prefix_num) - 1)) or (4294967295 - (2^(32 - prefix_num) - 1))
    local network = ip_num
    if bit32 then
        network = bit32.band(ip_num, mask)
    else
        -- Fallback for systems without bit32
        network = math.floor(ip_num / (2^(32 - prefix_num))) * (2^(32 - prefix_num))
    end
    
    return network, mask
end

-- Fungsi untuk cek apakah IP ada dalam range CIDR
function is_ip_in_range(ip, cidr)
    local ip_num = ip_to_number(ip)
    if not ip_num then return false end
    
    local network, mask = parse_cidr(cidr)
    if not network or not mask then return false end
    
    local masked_ip
    if bit32 then
        masked_ip = bit32.band(ip_num, mask)
    else
        -- Fallback calculation
        local prefix = cidr:match("/(%d+)")
        if prefix then
            local shift = 32 - tonumber(prefix)
            masked_ip = math.floor(ip_num / (2^shift)) * (2^shift)
        else
            return false
        end
    end
    
    return masked_ip == network
end

-- Fungsi untuk cek apakah IP di-whitelist (dengan dynamic loading)
function is_whitelisted_ip(ip)
    if not ip or ip == "" then return false end
    
    -- Load whitelist dari file jika perlu
    pcall(function() load_whitelist_from_file() end)
    
    -- Cek exact match dalam static whitelist
    if WHITELIST_IPS[ip] then
        return true
    end
    
    -- Cek exact match dalam dynamic whitelist
    if DYNAMIC_WHITELIST_IPS[ip] then
        return true
    end
    
    -- Cek range/CIDR static whitelist
    for _, range in ipairs(WHITELIST_RANGES) do
        if is_ip_in_range(ip, range) then
            return true
        end
    end
    
    -- Cek range/CIDR dynamic whitelist
    for _, range in ipairs(DYNAMIC_WHITELIST_RANGES) do
        if is_ip_in_range(ip, range) then
            return true
        end
    end
    
    return false
end

-- Fungsi untuk log whitelist access
function log_whitelisted_access(r, ip_address)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local method = r.method or "UNKNOWN"
    local uri = r.uri or "/"
    local query_string = r.args or ""
    local full_url = uri .. (query_string ~= "" and "?" .. query_string or "")
    
    local whitelist_log = string.format(
        "[%s] WHITELISTED | IP:%s | METHOD:%s | ROUTE:%s | REASON:IP_WHITELIST",
        timestamp,
        ip_address,
        method,
        full_url
    )
    
    log_message(whitelist_log, "access")
    log_message(whitelist_log, "user_activity")
end
function log_user_activity(r, fingerprint, bot_score, action, details)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local method = r.method or "UNKNOWN"
    local uri = r.uri or "/"
    local query_string = r.args or ""
    local full_url = uri .. (query_string ~= "" and "?" .. query_string or "")
    
    -- Format log aktivitas pengguna
    local activity_log = string.format(
        "[%s] ACTION:%s | IP:%s | METHOD:%s | ROUTE:%s | SCORE:%d%% | UA:%s | LANG:%s | ENC:%s | ACCEPT:%s | REFERER:%s | DETAILS:%s",
        timestamp,
        action,
        fingerprint.ip or "unknown",
        method,
        full_url,
        bot_score,
        (fingerprint.user_agent or "empty"):sub(1, 80),
        fingerprint.accept_language or "empty",
        fingerprint.accept_encoding or "empty", 
        fingerprint.accept or "empty",
        fingerprint.referer or "empty",
        details or ""
    )
    
    log_message(activity_log, "user_activity")
end

-- Fungsi untuk log aktivitas pengguna yang detail
function log_request_body(r, fingerprint, bot_score)
    local method = r.method or ""
    if method == "POST" or method == "PUT" or method == "PATCH" then
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")
        local uri = r.uri or "/"
        local content_type = "unknown"
        local content_length = "0"
        local body = "[BODY READING DISABLED - APACHE LUA LIMITATION]"
        
        -- Safely get headers
        if r.headers_in then
            content_type = r.headers_in["Content-Type"] or "unknown"
            content_length = r.headers_in["Content-Length"] or "0"
        end
        
        -- MODIFIKASI: Mencoba membaca body request
        local max_body_size = 10240 -- 10KB maksimal
        local content_length_num = tonumber(content_length) or 0
        
        if content_length_num > 0 and content_length_num <= max_body_size then
            local body_success, body_result = pcall(function()
                -- Metode 1: Gunakan r:body() jika tersedia (mod_lua 2.5+)
                if r.body then
                    return r:body()
                end
                
                -- Metode 2: Gunakan r:requestbody() jika tersedia
                if r.requestbody then
                    return r:requestbody()
                end
                
                -- Metode 3: Baca body sebagai file sementara
                local temp_file = os.tmpname()
                local success = r:requestbody(temp_file)
                if success then
                    local f = io.open(temp_file, "rb")
                    if f then
                        local content = f:read("*all")
                        f:close()
                        os.remove(temp_file)
                        return content
                    end
                    os.remove(temp_file)
                end
                
                return nil
            end)
            
            if body_success and body_result then
                -- Bersihkan dan amankan body untuk logging
                if #body_result > 1000 then
                    body_result = body_result:sub(1, 1000) .. "... [TRUNCATED]"
                end
                
                -- Ganti karakter non-printable dengan titik
                body_result = body_result:gsub("[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\xFF]", ".")
                
                body = body_result
            else
                body = "[BODY READ ERROR: " .. tostring(body_result) .. "]"
            end
        else
            if content_length_num == 0 then
                body = "[EMPTY BODY]"
            else
                body = "[BODY TOO LARGE: " .. content_length_num .. " bytes]"
            end
        end
        
        local body_log = string.format(
            "[%s] IP:%s | ROUTE:%s | METHOD:%s | SCORE:%d%% | CONTENT_TYPE:%s | CONTENT_LENGTH:%s | BODY:%s",
            timestamp,
            fingerprint.ip or "unknown",
            uri,
            method,
            bot_score,
            content_type,
            content_length,
            body
        )
        
        log_message(body_log, "request_body")
    end
end

-- Fungsi untuk log request yang diblokir
function log_blocked_request(r, fingerprint, bot_score, reason, ttl)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local method = r.method or "UNKNOWN"
    local uri = r.uri or "/"
    local query_string = r.args or ""
    local full_url = uri .. (query_string ~= "" and "?" .. query_string or "")
    
    local blocked_log = string.format(
        "[%s] BLOCKED | IP:%s | METHOD:%s | ROUTE:%s | SCORE:%d%% | REASON:%s | TTL:%ds | UA:%s | HEADERS:{LANG:%s,ENC:%s,ACCEPT:%s,REF:%s,SEC:{SITE:%s,MODE:%s,DEST:%s}}",
        timestamp,
        fingerprint.ip or "unknown",
        method,
        full_url,
        bot_score,
        reason,
        ttl,
        (fingerprint.user_agent or "empty"):sub(1, 100),
        fingerprint.accept_language or "empty",
        fingerprint.accept_encoding or "empty",
        fingerprint.accept or "empty", 
        fingerprint.referer or "empty",
        fingerprint.sec_fetch_site or "empty",
        fingerprint.sec_fetch_mode or "empty",
        fingerprint.sec_fetch_dest or "empty"
    )
    
    log_message(blocked_log, "blocked")
end

-- Fungsi untuk log akses yang berhasil
function log_successful_access(r, fingerprint, bot_score, count, max_requests)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local method = r.method or "UNKNOWN"
    local uri = r.uri or "/"
    local query_string = r.args or ""
    local full_url = uri .. (query_string ~= "" and "?" .. query_string or "")
    
    local access_log = string.format(
        "[%s] ALLOWED | IP:%s | METHOD:%s | ROUTE:%s | SCORE:%d%% | COUNT:%d/%d | UA:%s | REFERRER:%s",
        timestamp,
        fingerprint.ip or "unknown",
        method,
        full_url,
        bot_score,
        count,
        max_requests,
        (fingerprint.user_agent or "empty"):sub(1, 100),
        fingerprint.referer or "empty"
    )
    
    log_message(access_log, "access")
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
            <h1 class="error">?? Access Blocked</h1>
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

-- Fungsi untuk mendapatkan nilai header dengan error handling
function get_header_value(r, header_name)
    -- Protected call untuk menghindari error
    local success, result = pcall(function()
        if r.headers_in and r.headers_in[header_name] then
            return r.headers_in[header_name]
        end
        return nil
    end)
    
    if success and result then
        return result
    end
    
    -- Fallback ke subprocess_env
    success, result = pcall(function()
        local env_header_name = "HTTP_" .. header_name:gsub("-", "_"):upper()
        if r.subprocess_env and r.subprocess_env[env_header_name] then
            return r.subprocess_env[env_header_name]
        end
        return nil
    end)
    
    if success and result then
        return result
    end
    
    return nil
end

-- Fungsi utama untuk pengecekan akses
function check_access(r)

    -- Skip Cookies Request
    local should_skip, reason = should_skip_request(r)
    if should_skip then
        -- Log untuk debugging (opsional)
        pcall(function()
            log_message(string.format("SKIPPED: %s - %s", r.uri or "", reason), "main")
        end)
        return apache2.OK
    end

    -- Protected call untuk seluruh operasi
    local success, result = pcall(function()
        -- Dapatkan IP address dengan error handling
        local ip_address = nil
        
        -- Try different methods to get IP address
        if r.useragent_ip then
            ip_address = r.useragent_ip
        end
        
        if not ip_address then
            local headers_success, headers = pcall(function() return r.headers_in end)
            if headers_success and headers then
                if headers["X-Forwarded-For"] then
                    ip_address = headers["X-Forwarded-For"]:match("([^,]+)")
                elseif headers["X-Real-IP"] then
                    ip_address = headers["X-Real-IP"]
                elseif headers["CF-Connecting-IP"] then
                    ip_address = headers["CF-Connecting-IP"]
                end
            end
        end
        
        if not ip_address then
            local env_success, env = pcall(function() return r.subprocess_env end)
            if env_success and env and env["REMOTE_ADDR"] then
                ip_address = env["REMOTE_ADDR"]
            end
        end
        
        if not ip_address then
            return apache2.OK
        end

        -- Cek apakah IP di-whitelist
        if is_whitelisted_ip(ip_address) then
            log_whitelisted_access(r, ip_address)
            return apache2.OK
        end

        -- Kumpulkan semua headers untuk fingerprinting dengan error handling
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
        
        -- Log request body untuk method POST/PUT/PATCH (with error handling)
        pcall(function() log_request_body(r, fingerprint, bot_score) end)
        
        -- Bersihkan data expired secara berkala
        if math.random(20) == 1 then
            pcall(function() cleanup_expired_data() end)
        end

        local current_time = os.time()
        local last_time, count = read_counter(client_key)

        -- Reset hitungan jika sudah melewati BLOCK_TIME
        if last_time and (current_time - last_time) > BLOCK_TIME then
            count = 0
        end

        -- Simpan skor untuk analisis
        pcall(function() save_fingerprint_score(client_key, bot_score, fingerprint) end)

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
            -- Log request yang diblokir dengan detail lengkap (with error handling)
            pcall(function() log_blocked_request(r, fingerprint, bot_score, block_reason, ttl) end)
            
            -- Log ke user activity sebagai BLOCKED
            pcall(function() log_user_activity(r, fingerprint, bot_score, "BLOCKED", block_reason) end)
            
            -- Log ke main log (kompatibilitas dengan sistem lama)
            pcall(function() 
                log_message(string.format("BLOCKED - IP: %s, Score: %d%%, Count: %d/%d, Reason: %s, UA: %s", 
                    ip_address, bot_score, count, adjusted_max_requests, block_reason, 
                    fingerprint.user_agent:sub(1, 50)), "main")
            end)
            
            return send_blocked_response(r, ttl, bot_score, block_reason)
        end

        -- Update hitungan dan izinkan akses
        write_counter(client_key, current_time, count + 1)
        
        -- Log akses yang berhasil dengan detail lengkap (with error handling)
        pcall(function() log_successful_access(r, fingerprint, bot_score, count + 1, adjusted_max_requests) end)
        
        -- Log ke user activity sebagai ALLOWED
        pcall(function() 
            log_user_activity(r, fingerprint, bot_score, "ALLOWED", 
                string.format("Count: %d/%d", count + 1, adjusted_max_requests))
        end)
        
        -- Log ke main log (kompatibilitas dengan sistem lama)
        pcall(function()
            log_message(string.format("ALLOWED - IP: %s, Score: %d%%, Count: %d/%d, UA: %s", 
                ip_address, bot_score, count + 1, adjusted_max_requests, fingerprint.user_agent:sub(1, 50)), "main")
        end)
        
        return apache2.OK
    end)
    
    -- Jika ada error dalam pemrosesan, izinkan akses dan log error
    if not success then
        pcall(function() 
            log_message("ERROR in check_access: " .. tostring(result), "main") 
        end)
        return apache2.OK
    end
    
    return result
end