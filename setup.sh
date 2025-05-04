#!/bin/bash

# --- Настройка переменных ---
set -a
source .env || { echo "Файл .env не найден. Создайте его на основе .env.example"; exit 1; }
set +a

# --- Установка зависимых пакетов ---
sudo apt update
sudo apt install -y nodejs npm mysql-server

# --- Настройка MySQL ---
echo "Настройка MySQL..."

# Автоматическая инициализация, если MySQL установлен впервые
sudo systemctl start mysql

# Безопасная настройка (неинтерактивная версия mysql_secure_installation)
sudo mysql <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${DB_ROOT_PASSWORD}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF

# --- Установка зависимостей Node.js ---
npm install

# --- Создание systemd-сервиса ---
sudo tee /etc/systemd/system/auth-service.service > /dev/null <<EOF
[Unit]
Description=Auth Service
After=network.target

[Service]
EnvironmentFile=$(pwd)/.env
ExecStart=/usr/bin/node $(pwd)/src/server.js
WorkingDirectory=$(pwd)
Restart=always
User=${USER}

[Install]
WantedBy=multi-user.target
EOF

# --- Запуск сервиса ---
sudo systemctl daemon-reload
sudo systemctl enable auth-service
sudo systemctl restart auth-service

echo "Установка завершена! Сервис запущен."