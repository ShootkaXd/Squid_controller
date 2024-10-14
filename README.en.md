## Web application for proxy server management**
* Manage internet access within a local network
*
*
*

## Installation

To run the program in your local environment

Clone the repository:
https://github.com/ShootkaXd/Squid_controller.git

## START
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

*OR*

pip install -r requirements.txt

## Starting the server
* windows
1. Configure the host and local network in ```setting.py```
2. Install ```Nmap```
3. open ```cmd/PowerShall```
4. go to the project folder ```cd path\to\your```
5. activate virtual environment ```venv\Scripts\activate```
6. ```python app.py run```
* Ubuntu
1. Install necessary packages ```sudo apt install python3-pip python3-venv git nginx -y```
2. Install Samba ```sudo apt-get install samba```
3. Install ```sudo apt install nmap``` (If necessary)
4. Clone the repository
5. Go to the project folder ```cd path\to\your```
6. Configure the host and local network in the file ```seting.py```
7. Create a virtual environment ```python3 -m venv venv```
8. Activate the virtual environment ```source venv/bin/activate```
9. Install all dependencies ``` pip install -r requirements.txt ```
10. Run the server ```python app.py run```