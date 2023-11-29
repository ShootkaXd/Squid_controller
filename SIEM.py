import time


class SecurityEvent:
    def __init__(self, timestamp, source_ip, event_type, details):
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self.details = details


class SIEM:
    def __init__(self):
        self.security_events = []

    def log_event(self, source_ip, event_type, details):
        timestamp = time.time()
        event = SecurityEvent(timestamp, source_ip, event_type, details)
        self.security_events.append(event)
        self.process_event(event)

    def process_event(self, event):
        print(f"Received Event: {event.event_type} from {event.source_ip}. Details: {event.details}")

        # Пример простого анализа события
        if event.event_type == "Unauthorized Access":
            self.correlate_unauthorized_access(event)
        elif event.event_type == "Malware Detected":
            self.correlate_malware_detected(event)

    def correlate_unauthorized_access(self, event):
        # Пример корреляции для несанкционированного доступа
        correlated_events = [e for e in self.security_events if
                             e.event_type == "Failed Login" and e.source_ip == event.source_ip]

        if len(correlated_events) >= 3:
            self.react_to_unauthorized_access(event)

    def correlate_malware_detected(self, event):
        correlated_events = []

        # Проверяем наличие других событий Suspicious File Access для того же IP
        suspicious_file_events = [e for e in self.security_events if
                                  e.event_type == "Suspicious File Access" and e.source_ip == event.source_ip]
        correlated_events.extend(suspicious_file_events)

        # Проверяем наличие попыток обхода системы (например, множественные неудачные попытки входа)
        failed_login_events = [e for e in self.security_events if
                               e.event_type == "Failed Login" and e.source_ip == event.source_ip]
        if len(failed_login_events) >= 3:
            correlated_events.extend(failed_login_events)

        # Проверяем необычную активность (например, подозрительные запросы)
        unusual_activity_events = [e for e in self.security_events if
                                   e.event_type == "Unusual Activity" and e.source_ip == event.source_ip]
        correlated_events.extend(unusual_activity_events)

        # Проверяем подозрительные соединения (например, общение с известными зловредными IP-адресами)
        malicious_ip_addresses = ["malicious_ip_1", "malicious_ip_2"]
        malicious_connection_events = [e for e in self.security_events if
                                       e.source_ip == event.source_ip and e.details in malicious_ip_addresses]
        correlated_events.extend(malicious_connection_events)

        if len(correlated_events) >= 3:
            self.react_to_malware_detected(event)

    def react_to_unauthorized_access(self, event):
        # Пример реагирования на несанкционированный доступ
        print(f"Unauthorized Access Detected! Blocking IP: {event.source_ip}")

    def react_to_malware_detected(self, event):
        # Пример реагирования на обнаружение вредоносного ПО
        print(f"Malware Detected! Initiating Antivirus Scan for {event.source_ip}")

    def get_security_events(self):
        return self.security_events
