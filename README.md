# 🦑 Squid Controller – Web-панель управления прокси-сервером

![PyPI - Flask](https://img.shields.io/pypi/v/flask)
![PyPI - Scapy](https://img.shields.io/pypi/v/scapy?color=red)
![PyPI - Scanpy](https://img.shields.io/pypi/v/scanpy?color=blue)

## 🧩 Описание проекта

**Squid Controller** — это мощное веб-приложение для администрирования и мониторинга прокси-сервера **Squid**, предоставляющее:

- 🔐 Контроль доступа по MAC-адресам (ACL)
- 📡 Мониторинг активности пользователей в реальном времени
- 🖥️ Просмотр системной информации сервера
- 📊 SIEM-панель с экспортом логов и пользователей
- 📁 Интеграция с Nmap и Scapy для обнаружения новых устройств в сети

---

## 🚀 Возможности

- Управление доступом через веб-интерфейс
- Экспорт данных в JSON/CSV
- Система логирования
- Фоновое сканирование сети
- Реализация ограничения запросов (rate limiting)
- Интеграция с Squid через ACL-файл
- Локальная работа без интернета (офлайн-режим)

---

## ⚙️ Установка

> 💡 Вы можете воспользоваться автоматическим установщиком `install_full.sh`, если используете **Ubuntu** (рекомендуется).

### 🐧 Linux (Ubuntu)

```bash
# Установка зависимостей
sudo apt update
sudo apt install -y python3-pip python3-venv apache2 libapache2-mod-wsgi-py3 sqlite3 git unzip nmap

# Клонирование проекта
git clone https://github.com/ShootkaXd/Squid_controller.git
cd Squid_controller

# Создание виртуального окружения
python3 -m venv venv
source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt

# Создание базы данных
python3 -c "from database import db; db.create_all()"

# Настройка Squid (однократно)
sudo touch /etc/squid/allowed_macs.acl
sudo chown proxy:proxy /etc/squid/allowed_macs.acl
sudo bash -c "echo -e '\nacl allowed_macs arp \"/etc/squid/allowed_macs.acl\"\nhttp_access allow allowed_macs' >> /etc/squid/squid.conf"
sudo systemctl restart squid

# Запуск через Apache (рекомендуется) — см. раздел ниже
