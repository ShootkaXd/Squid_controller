import ipaddress
import aiosqlite
from scapy.layers.l2 import ARP, Ether, srp
import socket
import asyncio
from datetime import datetime
import subprocess
import logging
import settings

# Настройка логирования вместо использования print
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def get_hostname(ip_address):
    """
    Получает hostname устройства по IP-адресу через обратный DNS и NetBIOS.
    """
    hostname = await get_reverse_dns(ip_address)
    if hostname:
        return hostname

    hostname = await get_netbios_hostname(ip_address)
    if hostname:
        return hostname

    # Можно добавить дополнительные методы получения hostname здесь
    return None

async def get_reverse_dns(ip_address):
    """
    Пытается получить hostname через обратный DNS-запрос.
    """
    loop = asyncio.get_event_loop()
    try:
        hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip_address)
        logger.info(f"Reverse DNS: {ip_address} -> {hostname}")
        return hostname
    except socket.herror as e:
        logger.debug(f"Reverse DNS не найден для {ip_address}: {e}")
        return None
    except Exception as e:
        logger.error(f"Неизвестная ошибка при обратном DNS для {ip_address}: {e}")
        return None

async def get_netbios_hostname(ip_address):
    """
    Пытается получить hostname через NetBIOS с использованием nmblookup.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            'nmblookup', '-A', ip_address,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)

        if process.returncode == 0:
            for line in stdout.decode().splitlines():
                if '<00>' in line:
                    hostname = line.split()[0]
                    logger.info(f"NetBIOS: {ip_address} -> {hostname}")
                    return hostname
        else:
            logger.debug(f"nmblookup завершился с кодом {process.returncode} для {ip_address}")
            if stderr:
                logger.debug(f"stderr: {stderr.decode().strip()}")
    except asyncio.TimeoutError:
        logger.warning(f"nmblookup для {ip_address} превысил время ожидания")
    except FileNotFoundError:
        logger.error("nmblookup не найден. Убедитесь, что он установлен.")
    except Exception as e:
        logger.error(f"Ошибка при выполнении nmblookup для {ip_address}: {e}")
    return None

async def scan_local_network(ip):
    """
    Сканирует локальную сеть по заданному IP-диапазону и возвращает список устройств.
    """
    devices = []
    logger.info(f"Сканирование сети {ip}...")
    try:
        arp_request = ARP(pdst=ip)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

        # Отправляем ARP-запросы и получаем ответы
        result = srp(packet, timeout=5, verbose=0)[0]

        tasks = []
        for _, received in result:
            ip_address = received.psrc
            mac_address = received.hwsrc.upper() if received.hwsrc else "Неизвестно"
            tasks.append(process_device(ip_address, mac_address, devices))

        await asyncio.gather(*tasks)

    except Exception as e:
        logger.error(f"Ошибка во время сканирования сети: {e}")

    logger.info(f"Сканирование сети {ip} завершено. Найдено устройств: {len(devices)}")
    return devices

async def process_device(ip_address, mac_address, devices):
    """
    Обрабатывает обнаруженное устройство: получает hostname и добавляет его в список устройств.
    """
    hostname = await get_hostname(ip_address)
    devices.append({
        'ip': ip_address,
        'mac': mac_address,
        'hostname': hostname or "Неизвестно",
        'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'online'
    })

    logger.info(f"Обнаружено устройство: IP={ip_address}, MAC={mac_address}, hostname={hostname or 'Неизвестно'}")

async def update_database_with_devices():
    """
    Обновляет базу данных устройствами, найденными в текущем сканировании.
    """
    try:
        local_network_ip = settings.scan_network  # Например, '192.168.1.0/24'
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
        logger.error(f"Ошибка при обновлении базы данных: {e}")

async def upsert_device(cursor, device):
    """
    Вставляет новое устройство или обновляет существующее в базе данных.
    """
    ip_address = device['ip']
    mac_address = device['mac']
    hostname = device['hostname']
    last_seen = device['last_seen']
    status = device['status']

    if mac_address == "Неизвестно":
        await cursor.execute(
            '''
            INSERT INTO users (username, ip_address, mac_address, department, number_cabinet, hostname, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_address) DO UPDATE SET last_seen=excluded.last_seen, hostname=excluded.hostname, status=excluded.status
            ''',
            ("", ip_address, None, "", "", hostname, last_seen, status)
        )
    else:
        await cursor.execute('SELECT * FROM users WHERE mac_address = ?', (mac_address,))
        existing_device = await cursor.fetchone()

        if existing_device:
            await cursor.execute(
                '''
                UPDATE users
                SET last_seen = ?, hostname = ?, status = ?
                WHERE mac_address = ?
                ''',
                (last_seen, hostname, status, mac_address)
            )
        else:
            await cursor.execute(
                '''
                INSERT INTO users (username, ip_address, mac_address, department, number_cabinet, hostname, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                ("", ip_address, mac_address, "", "", hostname, last_seen, status)
            )

async def mark_offline_devices(cursor, scanned_macs):
    """
    Помечает устройства как оффлайн, если их MAC-адреса не были найдены в текущем сканировании.
    """
    # Получаем все MAC-адреса из базы данных
    await cursor.execute('SELECT mac_address FROM users WHERE mac_address IS NOT NULL')
    known_devices = await cursor.fetchall()

    for (mac_address,) in known_devices:
        if mac_address not in scanned_macs:
            await cursor.execute(
                '''
                UPDATE users
                SET status = ?
                WHERE mac_address = ?
                ''',
                ('offline', mac_address)
            )
