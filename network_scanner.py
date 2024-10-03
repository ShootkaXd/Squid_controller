import ipaddress
import aiosqlite
from scapy.layers.l2 import ARP, Ether, srp
import socket
from datetime import datetime

import setings


async def scan_local_network(ip):
    devices = []
    try:
        arp_request = ARP(pdst=ip)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request
        result = srp(packet, timeout=10, verbose=0)[0]

        for _, received in result:
            ip_address = received.psrc
            mac_address = received.hwsrc.upper()

            hostname = await get_hostname(ip_address)

            devices.append({
                'ip': ip_address,
                'mac': mac_address,
                'hostname': hostname or "Неизвестно",
                'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

    except Exception as e:
        print(f"Error during network scan: {e}")

    return devices


async def get_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return None


async def update_database_with_devices():
    try:
        local_network_ip = setings.scan_network
        devices = await scan_local_network(local_network_ip)
        devices.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))

        async with aiosqlite.connect('access_control.db') as conn:
            async with conn.cursor() as cursor:
                for device in devices:
                    await upsert_device(cursor, device)
                await conn.commit()

    except Exception as e:
        print(f"Error during database update: {e}")


async def upsert_device(cursor, device):
    ip_address = device['ip']
    mac_address = device['mac']
    hostname = device['hostname']
    last_seen = device['last_seen']

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
            ("", ip_address, mac_address, "", "", hostname, last_seen)
        )


def get_mac_address(ip_address):
    try:
        arp = ARP(pdst=ip_address)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0)[0]

        if result:
            return result[0][1].hwsrc.upper()
    except Exception as e:
        print(f"Error getting MAC address for {ip_address}: {e}")

    return None
