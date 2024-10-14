## Веб-приложение для управления прокси-сервером**
* Управлять доступом в интернет внутри локальной сети
* 
*
*

## Установка

Чтобы запустить программу в вашей локальной среде

    Клонировать репозиторий:
      https://github.com/ShootkaXd/Squid_controller.git

## НАЧАЛО
    1. python -m venv venv
    2. npm install chart.js
    3. pip install Flask-SSLify
    4. pip install scanpy
    6. pip install Flask-APScheduler
    7. pip install flask-socketio
    8. pip install Flask-Login
    9. pip install Flask-WTF
    10. pip install aiosqlite
    11. pip install scapy
    12. pip install psutil
    13. pip install Flask-Limiter
    14. python -m pip install requests
    15. pip install Flask-Limiter==1.3.0
    16. pip install Werkzeug
    17. pip install flask-admin
    18. pip install flask-security flask-sqlalchemy
    19. pip install Flask-SQLAlchemy
    20. pip install SQLAlchemy
    21. pip install zeroconf
    22. pip install scapy aiosqlite

*ИЛИ*

    pip install -r requirements.txt

## Запуск сервера
* windows
  1. Настройте хост и локальную сеть в файле ```seting.py```
  2. Установить ```Nmap``` 
  3. откройте ```cmd/PowerShall```
  4. перейдите в папку проекта ```cd path\to\your```
  5. активируйте виртуальную среду ```venv\Scripts\activate```
  6. ```python app.py run```
* Ubuntu
  1. Установить необходимые пакеты ```sudo apt install python3-pip python3-venv git nginx -y```
  2. Установить Samba ```sudo apt-get install samba```
  3. Установить  ```sudo apt install nmap``` (Если необходимо)
  4. Клонировать репозиторий 
  5. Перейдите в папку проекта ```cd path\to\your```
  6. Настройте хост и локальную сеть в файле ```seting.py```
  7. Создатие виртуального окружения ```python3 -m venv venv```
  8. Активируйте виртуальную среду ```source venv/bin/activate```
  9. Установить все зависимости ``` pip install -r requirements.txt ```
  10. Запустить сервер ```python app.py run```
