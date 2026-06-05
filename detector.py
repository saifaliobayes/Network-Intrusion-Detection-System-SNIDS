from database import DatabaseManager
from datetime import datetime, timedelta


class IntrusionDetector:
    def __init__(self):
        self.global_requests = []
        self.database = DatabaseManager()
        self.ip_requests = {}
        self.ip_ports = {}
        self.blocked_ips = set()
        self.FLOOD_THRESHOLD = 5
        self.PORTSCAN_THRESHOLD = 4
        self.on_attack_detected = None

    def clean_old_requests(self, ip):
        now = datetime.now()
        window = timedelta(seconds=10)
        if ip in self.ip_requests:
            self.ip_requests[ip] = [t for t in self.ip_requests[ip] if now - t <= window]

    def clean_old_ports(self, ip):
        now = datetime.now()
        window = timedelta(seconds=10)
        if ip in self.ip_ports:
            self.ip_ports[ip] = [(port, t) for port, t in self.ip_ports[ip] if now - t <= window]

    def process_packet(self, packet):
        ip = packet["ip"]
        port = packet.get("port")
        now = datetime.now()
        self.global_requests.append({"ip": ip, "time": now})
        if ip not in self.ip_requests:
            self.ip_requests[ip] = []
        if ip not in self.ip_ports:
            self.ip_ports[ip] = []
        self.ip_requests[ip].append(now)
        if port is not None:
            self.ip_ports[ip].append((port, now))
        self.detect_flood(ip)
        self.detect_port_scan(ip)

    def detect_flood(self, ip):
        """كشف الـ Flood — بدون حظر تلقائي."""
        self.clean_old_requests(ip)
        count = len(self.ip_requests[ip])
        if count > self.FLOOD_THRESHOLD:
            self.save_log("FLOOD ATTACK", ip, "HIGH")
            if self.on_attack_detected:
                self.on_attack_detected("FLOOD ATTACK", ip, "HIGH", count)

    def detect_port_scan(self, ip):
        """كشف الـ Port Scan — بدون حظر تلقائي."""
        self.clean_old_ports(ip)
        unique_ports = set(port for port, t in self.ip_ports[ip])
        if len(unique_ports) >= self.PORTSCAN_THRESHOLD:
            self.save_log("PORT SCAN", ip, "MEDIUM")
            if self.on_attack_detected:
                self.on_attack_detected("PORT SCAN", ip, "MEDIUM", len(unique_ports))
            self.ip_ports[ip] = []

    def save_log(self, attack_type, ip, severity):
        now = datetime.now()
        self.database.save_attack(
            date=now.strftime("%Y-%m-%d"),
            time=now.strftime("%H:%M:%S"),
            day=now.strftime("%A"),
            ip=ip,
            attack_type=attack_type,
            severity=severity,
        )

    def get_ip_request_count(self, ip):
        self.clean_old_requests(ip)
        return len(self.ip_requests.get(ip, []))
