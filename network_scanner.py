import ipaddress
import aiosqlite
from scapy.layers.l2 import ARP, Ether, srp
import socket
from datetime import datetime
import asyncio

import settings


async def send_arp_request(ip):
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    return srp(packet, timeout=1, verbose=0)[0]  # Уменьшено время ожидания


async def scan_local_network(ip_range):
    devices = []
    tasks = []

    for ip in ip_range:
        tasks.append(send_arp_request(ip))

    results = await asyncio.gather(*tasks)

    for result in results:
        for sent, received in result:
            ip_address = received.psrc
            mac_address = received.hwsrc.upper()

            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                hostname = None

            devices.append({
                'ip': ip_address,
                'mac': mac_address,
                'hostname': hostname,
                'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

    return devices


async def update_database_with_devices():
    try:
        local_network_ip = setings.scan_network
        ip_range = [str(ip) for ip in ipaddress.IPv4Network(local_network_ip)]
        devices = await scan_local_network(ip_range)

        devices.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))

        async with aiosqlite.connect('access_control.db') as conn:
            async with conn.cursor() as cursor:
                for device in devices:
                    ip_address = device['ip']
                    mac_address = device['mac']
                    hostname = device['hostname'] or "Неизвестно"
                    last_seen = device['last_seen']
                    username = ""
                    department = ""
                    number_cabinet = ""

                    await cursor.execute('SELECT * FROM users WHERE mac_address = ?', (mac_address,))
                    existing_device = await cursor.fetchone()

                    if existing_device:
                        await cursor.execute(
                            'UPDATE users SET last_seen = ?, hostname = ? WHERE mac_address = ?',
                            (last_seen, hostname, mac_address)
                        )
                    else:
                        await cursor.execute(
                            'INSERT INTO users (username, ip_address, mac_address, department, number_cabinet, '
                            'hostname, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)',
                            (username, ip_address, mac_address, department, number_cabinet, hostname, last_seen))
                await conn.commit()
    except Exception as e:
        print(f"Error during database update: {e}")


def get_mac_address(ip_address):
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=1, verbose=0)[0]  # Уменьшено время ожидания

    if result:
        mac_address = result[0][1].hwsrc.upper()
        return mac_address
    else:
        return None