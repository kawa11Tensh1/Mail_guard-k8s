# Используем базовый образ PHP 8.3 FPM
FROM php:8.3-fpm

# Устанавливаем Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Устанавливаем Symfony CLI
RUN curl -sS https://get.symfony.com/cli/installer | bash

# Копируем файлы приложения в контейнер
COPY . /app
# Копируем конфигурационный файл PHP
COPY ./php.ini /usr/local/etc/php/php.ini

# Переходим в рабочую директорию приложения
WORKDIR /app

# Открываем порт 8000 для доступа извне контейнера
# Если нужен другой порт, измените значение здесь
EXPOSE 8000

# Устанавливаем права доступа на директории
RUN mkdir -p /var/www/html/var/cache/dev /var/www/html/var/log
RUN chown -R www-data:www-data /var/www/html/var/cache /var/www/html/var/log

# Проверяем, что php.ini подгружается правильно
RUN php --ini

# Здесь можно добавить команду для запуска вашего приложения
# Например:
CMD ["php", "-S", "0.0.0.0:8000", "-t", "public"]
