#!/bin/bash

# Установка зависимостей
sudo apt update
sudo apt install -y nodejs npm

# Установка модулей проекта
npm install

mkdir -p src/public/uploads

# Создание systemd-сервиса
sudo tee /etc/systemd/system/auth-service.service > /dev/null <<EOF
[Unit]
Description=Minecraft Auth Service
After=network.target

[Service]
ExecStart=$(which node) $(pwd)/src/server.js
WorkingDirectory=$(pwd)
Restart=always
User=$(whoami)

# Для работы с SQLite
Environment="NODE_ENV=production"
Environment="DB_PATH=$(pwd)/auth.db"

[Install]
WantedBy=multi-user.target
EOF

# Перезагрузка демонов и запуск
sudo systemctl daemon-reload
sudo systemctl enable auth-service
sudo systemctl start auth-service

echo "Сервис установлен и добавлен в автозагрузку!"
echo "Для проверки: sudo systemctl status auth-service"