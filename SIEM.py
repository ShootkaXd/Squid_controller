import psutil
from datetime import datetime

previous_network_traffic = {}


class SIEM:
    def __init__(self):
        self.events = []

    def log_event(self, event_type, source_ip, username, description):
        current_time = datetime.now().isoformat()
        event_data = {
            "event_type": event_type,
            "timestamp": current_time,
            "source_ip": source_ip,
            "username": username,
            "description": description
        }
        self.events.append(event_data)

    def get_events(self):
        return self.events


def check_anomalous_traffic():
    network_info = psutil.net_io_counters(pernic=True)

    for interface, traffic in network_info.items():
        if interface not in previous_network_traffic:
            previous_network_traffic[interface] = traffic
            continue

        current_sent_bytes, current_received_bytes = traffic.bytes_sent, traffic.bytes_recv
        previous_sent_bytes, previous_received_bytes = previous_network_traffic[interface]

        if (current_sent_bytes - previous_sent_bytes) > 0.5 * previous_sent_bytes or \
                (current_received_bytes - previous_received_bytes) > 0.5 * previous_received_bytes:
            event_type = "Anomalous Network Traffic"
            timestamp = datetime.now().isoformat()
            source_ip = "N/A"  # логика для определения источника IP
            username = "N/A"  # логика для определения пользователя
            description = f"Anomalous traffic on interface {interface}"

            print(
                f"Event: {event_type}, Timestamp: {timestamp}, Source IP: {source_ip}, Username: {username}, Description: {description}")

        previous_network_traffic[interface] = (current_sent_bytes, current_received_bytes)
