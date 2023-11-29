import aiosqlite
from scapy.layers.l2 import ARP, Ether, srp


async def scan_local_network(ip):
    try:
        arp_request = ARP(pdst=ip)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

        packet = ether_frame / arp_request
        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc.upper()})

        return devices
    except Exception as e:
        print(f"Error during network scan: {e}")


async def update_database_with_devices():
    try:
        local_network_ip = "192.168.118.0/24"
        devices = await scan_local_network(local_network_ip)

        async with aiosqlite.connect('access_control.db') as conn:
            async with conn.cursor() as cursor:
                for device in devices:
                    ip_address = device['ip']
                    mac_address = device['mac']
                    username = ""
                    department = ""
                    number_cabinet = ""

                    await cursor.execute('SELECT * FROM users WHERE mac_address = ?', (mac_address,))
                    existing_device = await cursor.fetchone()

                    if not existing_device:
                        await cursor.execute(
                            'INSERT INTO users (username, ip_address, mac_address, department, number_cabinet) VALUES (?, ?, ?, ?, ?)',
                            (username, ip_address, mac_address, department, number_cabinet))
                        await conn.commit()
    except Exception as e:
        print(f"Error during database update: {e}")


def get_mac_address(ip_address):
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    if result:
        mac_address = result[0][1].hwsrc.upper()
        return mac_address
    else:
        return None
