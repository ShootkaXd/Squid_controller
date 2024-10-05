import ipaddress
import aiosqlite
from scapy.layers.l2 import ARP, Ether, srp
import socket
import asyncio
from datetime import datetime
import settings


async def get_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return None


async def scan_local_network(ip):
    devices = []
    print(f"Сканирование сети {ip}...")  # Вывод информации о начале сканирования
    try:
        arp_request = ARP(pdst=ip)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request
        result = srp(packet, timeout=5, verbose=0)[0]

        for _, received in result:
            ip_address = received.psrc
            mac_address = received.hwsrc.upper() if received.hwsrc else "Неизвестно"
            hostname = await get_hostname(ip_address)

            devices.append({
                'ip': ip_address,
                'mac': mac_address,
                'hostname': hostname or "Неизвестно",
                'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'online'
            })

            print(
                f"Обнаружено устройство: IP={ip_address}, MAC={mac_address}, hostname={hostname}")  # Вывод информации о каждом найденном устройстве

    except Exception as e:
        print(f"Ошибка во время сканирования сети: {e}")

    print(
        f"Сканирование сети {ip} завершено. Найдено устройств: {len(devices)}")  # Вывод информации о завершении сканирования
    return devices


async def update_database_with_devices():
    try:
        local_network_ip = settings.scan_network
        scanned_devices = await scan_local_network(local_network_ip)
        scanned_macs = {device['mac'] for device in scanned_devices if device['mac'] != "Неизвестно"}

        async with aiosqlite.connect('access_control.db') as conn:
            async with conn.cursor() as cursor:
                # Обновляем или вставляем устройства, найденные в текущем сканировании
                for device in scanned_devices:
                    await upsert_device(cursor, device)

                # Помечаем устройства как оффлайн, которые не были найдены в текущем сканировании
                await mark_offline_devices(cursor, scanned_macs)

                await conn.commit()

    except Exception as e:
        print(f"Ошибка при обновлении базы данных: {e}")


async def upsert_device(cursor, device):
    ip_address = device['ip']
    mac_address = device['mac']
    hostname = device['hostname']
    last_seen = device['last_seen']
    status = device['status']

    if mac_address == "Неизвестно":
        await cursor.execute(
            'INSERT INTO users (username, ip_address, mac_address, department, number_cabinet, hostname, last_seen, status) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?) '
            'ON CONFLICT(mac_address) DO UPDATE SET last_seen=excluded.last_seen, hostname=excluded.hostname, status=excluded.status',
            ("", ip_address, None, "", "", hostname, last_seen, status)
        )
    else:
        await cursor.execute('SELECT * FROM users WHERE mac_address = ?', (mac_address,))
        existing_device = await cursor.fetchone()

        if existing_device:
            await cursor.execute(
                'UPDATE users SET last_seen = ?, hostname = ?, status = ? WHERE mac_address = ?',
                (last_seen, hostname, status, mac_address)
            )
        else:
            await cursor.execute(
                'INSERT INTO users (username, ip_address, mac_address, department, number_cabinet, hostname, last_seen, status) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                ("", ip_address, mac_address, "", "", hostname, last_seen, status)
            )


async def mark_offline_devices(cursor, scanned_macs):
    # Получаем все MAC-адреса из базы данных
    await cursor.execute('SELECT mac_address FROM users WHERE mac_address IS NOT NULL')
    known_devices = await cursor.fetchall()

    for (mac_address,) in known_devices:
        if mac_address not in scanned_macs:
            await cursor.execute(
                'UPDATE users SET status = ? WHERE mac_address = ?',
                ('offline', mac_address)
            )
