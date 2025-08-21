FROM php:8.2-apache

# Update & install dependencies
RUN apt-get update && apt-get install -y \
    libzip-dev \
    unzip \
    libonig-dev \
    libicu-dev \
    libbz2-dev \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    g++ && \
    rm -rf /var/lib/apt/lists/*

# Direktori untuk Lua & logs
RUN mkdir -p /etc/apache2/lua \
    && mkdir -p /var/log/apache2/lua

# Direktori Logs Apache Untuk Lua
RUN mkdir -p /etc/apache2/logs && \
    chown -R www-data:www-data /etc/apache2/logs && \
    chmod -R 777 /etc/apache2/logs


# Copy Lua & config
COPY fingerprint.lua /etc/apache2/lua/fingerprint.lua
COPY fingerprint.conf /etc/apache2/conf-available/fingerprint.conf

# Aktifkan modul Apache & konfigurasi
RUN a2enmod lua unique_id rewrite headers && \
    a2enconf fingerprint

# Buat file log dengan permission www-data
RUN touch /var/log/apache2/lua/apache_antibrute.log && \
    touch /var/log/apache2/lua/apache_antibrute_data.txt && \
    chown -R www-data:www-data /var/log/apache2/lua && \
    chmod -R 777 /var/log/apache2/lua

# Set document root ke /var/www/html/public
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf
RUN sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Gunakan php.ini-development
RUN mv "$PHP_INI_DIR/php.ini-development" "$PHP_INI_DIR/php.ini"

# Copy contoh web
COPY public/ /var/www/html/public/

# Jalankan sebagai www-data
USER www-data
