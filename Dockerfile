FROM php:8.2-apache

# Install system deps + PHP extensions
RUN apt-get update && apt-get install -y \
      libpq-dev \
      libcurl4-openssl-dev \
      libssl-dev \
    && docker-php-ext-install pdo pdo_mysql pdo_pgsql curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite headers

# PHP: never display errors to browser, always log them
RUN echo "display_errors = Off" >> /usr/local/etc/php/conf.d/nexus.ini \
 && echo "log_errors = On"      >> /usr/local/etc/php/conf.d/nexus.ini \
 && echo "error_reporting = E_ALL" >> /usr/local/etc/php/conf.d/nexus.ini

# Apache config: document root → /var/www/html/public
# AllowOverride All so .htaccess is respected (critical for PassengerErrorPage off)
RUN sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html/public|g' \
      /etc/apache2/sites-available/000-default.conf \
 && sed -i 's|<Directory /var/www/html>|<Directory /var/www/html/public>|g' \
      /etc/apache2/apache2.conf \
 && sed -i 's|AllowOverride None|AllowOverride All|g' \
      /etc/apache2/apache2.conf

# Disable Apache's built-in error documents — let PHP output pass through
RUN echo 'ErrorDocument 500 " "' >> /etc/apache2/conf-available/nexus.conf \
 && echo 'ErrorDocument 404 " "' >> /etc/apache2/conf-available/nexus.conf \
 && a2enconf nexus

COPY . /var/www/html/

# Security: deny direct access to non-public directories
RUN printf '<Directory /var/www/html/src>\n  Require all denied\n</Directory>\n\
<Directory /var/www/html/config>\n  Require all denied\n</Directory>\n' \
  >> /etc/apache2/apache2.conf

RUN chown -R www-data:www-data /var/www/html \
 && chmod -R 755 /var/www/html \
 && chmod 640 /var/www/html/config/config.php

EXPOSE 80
