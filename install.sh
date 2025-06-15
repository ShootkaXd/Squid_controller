#!/bin/bash

set -e

APP_DIR="/opt/access_control"
VENV_DIR="$APP_DIR/venv"

echo "🔧 Установка зависимостей..."
sudo apt update
sudo apt install -y apache2 libapache2-mod-wsgi-py3 python3 python3-pip python3-venv sqlite3 unzip

echo "📂 Создание папки проекта: $APP_DIR"
sudo mkdir -p "$APP_DIR"
sudo cp -r ./* "$APP_DIR"
cd "$APP_DIR"

echo "📦 Создание виртуального окружения..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "📦 Установка Python-библиотек..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🗃️ Проверка базы данных..."
if [ ! -f access_control.db ]; then
  python3 -c 'from database import db; db.create_all()'
fi

echo "🌐 Настройка Apache..."
WSGI_FILE="$APP_DIR/app.wsgi"
cat > "$WSGI_FILE" <<EOF
import sys
sys.path.insert(0, '$APP_DIR')
from app import app as application
EOF

APACHE_CONF="/etc/apache2/sites-available/access-control.conf"
sudo tee "$APACHE_CONF" > /dev/null <<EOL
<VirtualHost *:80>
    ServerName localhost

    WSGIDaemonProcess access_control python-home=$VENV_DIR python-path=$APP_DIR
    WSGIScriptAlias / $APP_DIR/app.wsgi

    <Directory $APP_DIR>
        Require all granted
    </Directory>

    Alias /static $APP_DIR/static
    <Directory $APP_DIR/static>
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/access_control_error.log
    CustomLog \${APACHE_LOG_DIR}/access_control_access.log combined
</VirtualHost>
EOL

echo "🚀 Активация сайта..."
sudo a2enmod wsgi
sudo a2ensite access-control.conf
sudo a2dissite 000-default.conf
sudo systemctl restart apache2

echo "✅ Установка завершена!"
IP=$(hostname -I | awk '{print $1}')
echo "🌍 Приложение доступно: http://$IP/"
