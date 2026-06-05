import sqlite3
import threading
from datetime import datetime


class DatabaseManager:
    def __init__(self, db_path="network.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.create_table()

    def _conn(self):
        """connection جديد لكل thread — يحل مشكلة Recursive cursor."""
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def create_table(self):
        with self._lock:
            con = self._conn()
            con.execute("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT, time TEXT, day TEXT,
                    ip TEXT, attack_type TEXT, severity TEXT
                )
            """)
            con.commit()
            con.close()

    def save_attack(self, date, time, day, ip, attack_type, severity):
        with self._lock:
            con = self._conn()
            con.execute("""
                INSERT INTO attacks (date, time, day, ip, attack_type, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (date, time, day, ip, attack_type, severity))
            con.commit()
            con.close()

    def get_recent_attacks(self, limit=50):
        with self._lock:
            con = self._conn()
            cur = con.execute(
                "SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            con.close()
        columns = ["id", "date", "time", "day", "ip", "attack_type", "severity"]
        return [dict(zip(columns, row)) for row in rows]

    def get_all_attacks(self):
        with self._lock:
            con = self._conn()
            cur = con.execute("SELECT * FROM attacks ORDER BY id DESC")
            rows = cur.fetchall()
            con.close()
        columns = ["id", "date", "time", "day", "ip", "attack_type", "severity"]
        return [dict(zip(columns, row)) for row in rows]

    def get_total_count(self):
        with self._lock:
            con = self._conn()
            cur = con.execute("SELECT COUNT(*) FROM attacks")
            count = cur.fetchone()[0]
            con.close()
        return count

    def get_attack_counts_by_type(self):
        with self._lock:
            con = self._conn()
            cur = con.execute(
                "SELECT attack_type, COUNT(*) FROM attacks GROUP BY attack_type ORDER BY COUNT(*) DESC")
            rows = cur.fetchall()
            con.close()
        return rows

    def get_attack_counts_by_ip(self):
        with self._lock:
            con = self._conn()
            cur = con.execute(
                "SELECT ip, COUNT(*) FROM attacks GROUP BY ip ORDER BY COUNT(*) DESC")
            rows = cur.fetchall()
            con.close()
        return rows

    def clear_all(self):
        with self._lock:
            con = self._conn()
            con.execute("DELETE FROM attacks")
            con.commit()
            con.close()

    def show_attacks(self):
        for a in self.get_all_attacks():
            print(a)

    def close(self):
        pass  # لا يوجد connection دائم
