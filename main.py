import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import random
import time
import datetime
import collections
import csv
import os

from detector import IntrusionDetector

# ───scapy ──────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ─── Palette ───────────────────────────────────────────────
BG_DARK    = "#1e1e2e"
BG_PANEL   = "#2a2a3e"
BG_CARD    = "#252538"
BG_TABLE   = "#1a1a2a"
ACCENT     = "#00d4ff"
SUCCESS    = "#00e676"
WARNING    = "#ff9800"
DANGER     = "#ff4444"
TEXT_MAIN  = "#e0e0e0"
TEXT_DIM   = "#7a8899"
BORDER     = "#3a3a50"
SEV_HIGH   = "#ff4444"
SEV_MED    = "#ff9800"
SEV_LOW    = "#00e676"

FONT_SUB   = ("Courier New", 10, "bold")
FONT_MONO  = ("Courier New", 9)
FONT_LABEL = ("Courier New", 9)
FONT_SMALL = ("Courier New", 8)

FAKE_IPS = [
    "192.168.1.10", "10.0.0.5", "172.16.0.3", "8.8.8.8",
    "45.33.32.156", "185.220.101.20", "203.0.113.55", "198.51.100.9",
    "192.168.1.20", "10.10.1.5"
]
PORTS = [22, 23, 80, 443, 3306, 8080, 21, 25, 3389, 5900]


class SNIDS_App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SNIDS — Smart Network Intrusion Detection System")
        self.geometry("1280x760")
        self.minsize(1000, 640)
        self.configure(bg=BG_DARK)

        self.monitoring  = False
        self.live_mode   = tk.StringVar(value="simulate")  # "simulate" | "live"
        self.ip_hits     = collections.Counter()
        self.total_pkts  = 0   

        self.detector = IntrusionDetector()
        self.detector.on_attack_detected = self._on_attack

        self._apply_styles()
        self._build_ui()
        self._update_clock()
        self._refresh_table()

    # ── Styles ─────────────────────────────────────────────
    def _apply_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview",
                    background=BG_TABLE, foreground=TEXT_MAIN,
                    fieldbackground=BG_TABLE, font=FONT_MONO,
                    rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading",
                    background=BG_PANEL, foreground=ACCENT,
                    font=("Courier New", 9, "bold"), relief="flat")
        s.map("Treeview",
              background=[("selected", "#2d2d4a")],
              foreground=[("selected", ACCENT)])
        s.configure("Vertical.TScrollbar",
                    background=BG_PANEL, troughcolor=BG_DARK,
                    arrowcolor=TEXT_DIM, borderwidth=0, width=8)

    # ── Build UI ───────────────────────────────────────────
    def _build_ui(self):
        self._build_topbar()
        self._build_toolbar()
        body = tk.Frame(self, bg=BG_DARK)
        body.pack(fill="both", expand=True, padx=14, pady=(4, 14))
        body.columnconfigure(0, weight=7)
        body.columnconfigure(1, weight=3)
        body.rowconfigure(0, weight=1)
        self._build_table(body)
        self._build_sidebar(body)

    def _build_topbar(self):
        bar = tk.Frame(self, bg=BG_PANEL, height=52)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Label(bar, text="  ⬡", font=("Courier New", 20, "bold"),
                 fg=ACCENT, bg=BG_PANEL).pack(side="left", pady=8)
        tk.Label(bar, text=" SNIDS", font=("Courier New", 14, "bold"),
                 fg=ACCENT, bg=BG_PANEL).pack(side="left")
        tk.Label(bar, text="   Smart Network Intrusion Detection System",
                 font=FONT_LABEL, fg=TEXT_DIM, bg=BG_PANEL).pack(side="left")
        self.clock_lbl = tk.Label(bar, text="", font=FONT_MONO,
                                   fg=ACCENT, bg=BG_PANEL)
        self.clock_lbl.pack(side="right", padx=18)
        tk.Frame(self, bg=ACCENT, height=2).pack(fill="x")

    def _build_toolbar(self):
        bar = tk.Frame(self, bg=BG_PANEL, height=46)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        inner = tk.Frame(bar, bg=BG_PANEL)
        inner.pack(side="left", padx=12, pady=6)

        # ── ──────────────────────────────────
        mode_frame = tk.Frame(inner, bg=BG_CARD,
                               highlightthickness=1, highlightbackground=BORDER)
        mode_frame.pack(side="left", padx=(0, 10))

        tk.Label(mode_frame, text=" Mode:", font=FONT_SMALL,
                 fg=TEXT_DIM, bg=BG_CARD).pack(side="left", padx=(6, 2))

        self.rb_sim = tk.Radiobutton(
            mode_frame, text="Simulate", variable=self.live_mode,
            value="simulate", font=FONT_SMALL,
            bg=BG_CARD, fg=TEXT_DIM,
            selectcolor=BG_DARK, activebackground=BG_CARD,
            activeforeground=ACCENT,
            command=self._on_mode_change)
        self.rb_sim.pack(side="left", padx=4)

        live_text = "Live (scapy)" if SCAPY_AVAILABLE else "Live (no scapy)"
        live_color = SUCCESS if SCAPY_AVAILABLE else TEXT_DIM
        self.rb_live = tk.Radiobutton(
            mode_frame, text=live_text, variable=self.live_mode,
            value="live", font=FONT_SMALL,
            bg=BG_CARD, fg=live_color,
            selectcolor=BG_DARK, activebackground=BG_CARD,
            activeforeground=ACCENT,
            state="normal" if SCAPY_AVAILABLE else "disabled",
            command=self._on_mode_change)
        self.rb_live.pack(side="left", padx=(0, 6))

        
        self.mode_dot = tk.Label(mode_frame, text="●", font=FONT_SMALL,
                                  fg=ACCENT, bg=BG_CARD)
        self.mode_dot.pack(side="left", padx=(0, 6))

        
        tk.Frame(inner, bg=BORDER, width=1, height=26).pack(side="left", padx=8)

        # ──Start / Stop ─────────────────────────────
        self.btn_start = self._btn(inner, "▶  Start", self._start, SUCCESS)
        self.btn_start.pack(side="left", padx=(0, 4))
        self.btn_stop  = self._btn(inner, "■  Stop",  self._stop,  DANGER, state="disabled")
        self.btn_stop.pack(side="left", padx=(0, 10))

        
        tk.Frame(inner, bg=BORDER, width=1, height=26).pack(side="left", padx=8)

        # ── IP + Block / Unblock ───────────────────────
        tk.Label(inner, text="IP:", font=FONT_LABEL,
                 fg=TEXT_DIM, bg=BG_PANEL).pack(side="left", padx=(8, 4))
        self.ip_entry = tk.Entry(
            inner, font=FONT_MONO, bg=BG_DARK, fg=TEXT_MAIN,
            insertbackground=ACCENT, relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT, bd=4, width=17)
        self.ip_entry.pack(side="left", padx=(0, 6))

        self._btn(inner, " Block",   self._block_ip,   DANGER).pack(side="left", padx=3)
        self._btn(inner, " Unblock", self._unblock_ip, SUCCESS).pack(side="left", padx=3)

        # فاصل
        tk.Frame(inner, bg=BORDER, width=1, height=26).pack(side="left", padx=8)

        self._btn(inner, " Refresh",    self._refresh_table, ACCENT).pack(side="left", padx=3)
        self._btn(inner, "💾 Export CSV", self._export_csv,    WARNING).pack(side="left", padx=3)
        self._btn(inner, "🗑 Clear DB",   self._clear_db,      DANGER).pack(side="left", padx=3)

        
        self.db_count_lbl = tk.Label(bar, text="", font=FONT_SMALL,
                                      fg=TEXT_DIM, bg=BG_PANEL)
        self.db_count_lbl.pack(side="right", padx=16)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    # ── Table ──────────────────────────────────────────────
    def _build_table(self, parent):
        card = tk.Frame(parent, bg=BG_CARD,
                        highlightthickness=1, highlightbackground=BORDER)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        card.rowconfigure(1, weight=1)
        card.columnconfigure(0, weight=1)

        hdr = tk.Frame(card, bg=BG_PANEL, height=34)
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  🗄  Attack History", font=FONT_SUB,
                 fg=ACCENT, bg=BG_PANEL).pack(side="left", padx=12, pady=7)

    
        self.pkt_count_lbl = tk.Label(hdr, text="", font=FONT_SMALL,
                                       fg=TEXT_DIM, bg=BG_PANEL)
        self.pkt_count_lbl.pack(side="right", padx=12)

        cols = [
            ("id",          "#",           42,  "center"),
            ("date",        "Date",        105, "center"),
            ("time",        "Time",         80, "center"),
            ("day",         "Day",          90, "center"),
            ("ip",          "IP Address",  145, "center"),
            ("attack_type", "Attack Type", 170, "center"),
            ("severity",    "Severity",     90, "center"),
        ]
        self.hist_tree = ttk.Treeview(
            card, columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for cid, txt, w, anc in cols:
            self.hist_tree.heading(cid, text=txt)
            self.hist_tree.column(cid, width=w, anchor=anc, minwidth=w)

        self.hist_tree.tag_configure("HIGH",   foreground=SEV_HIGH, background="#2a1a1a")
        self.hist_tree.tag_configure("MEDIUM", foreground=SEV_MED,  background="#2a2010")
        self.hist_tree.tag_configure("LOW",    foreground=SEV_LOW,  background="#1a2a1a")

        vsb = ttk.Scrollbar(card, orient="vertical", command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=vsb.set)
        self.hist_tree.grid(row=1, column=0, sticky="nsew", padx=(6, 0), pady=6)
        vsb.grid(row=1, column=1, sticky="ns", pady=6, padx=(0, 4))

    # ── Sidebar ────────────────────────────────────────────
    def _build_sidebar(self, parent):
        side = tk.Frame(parent, bg=BG_DARK)
        side.grid(row=0, column=1, sticky="nsew")
        side.rowconfigure(0, weight=3)
        side.rowconfigure(1, weight=2)
        side.columnconfigure(0, weight=1)

        # Alerts
        a_card = tk.Frame(side, bg=BG_CARD,
                          highlightthickness=1, highlightbackground=DANGER)
        a_card.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        a_card.rowconfigure(1, weight=1)
        a_card.columnconfigure(0, weight=1)

        a_hdr = tk.Frame(a_card, bg=BG_PANEL, height=34)
        a_hdr.grid(row=0, column=0, sticky="ew")
        a_hdr.pack_propagate(False)
        tk.Label(a_hdr, text="    Alerts & Threats", font=FONT_SUB,
                 fg=DANGER, bg=BG_PANEL).pack(side="left", padx=10, pady=7)
        self._small_btn(a_hdr, "Clear", self._clear_alerts, TEXT_DIM).pack(
            side="right", padx=8, pady=7)

        self.alert_box = scrolledtext.ScrolledText(
            a_card, bg="#1c0e0e", fg="#ff8080", font=FONT_MONO,
            relief="flat", wrap="word", cursor="arrow",
            selectbackground="#2a1a1a")
        self.alert_box.grid(row=1, column=0, sticky="nsew", padx=6, pady=(2, 6))
        self.alert_box.configure(state="disabled")
        self.alert_box.tag_config("high",    foreground=SEV_HIGH)
        self.alert_box.tag_config("medium",  foreground=SEV_MED)
        self.alert_box.tag_config("success", foreground=SUCCESS)
        self.alert_box.tag_config("dim",     foreground=TEXT_DIM)
        self.alert_box.tag_config("info",    foreground=ACCENT)

        # Blocked IPs
        b_card = tk.Frame(side, bg=BG_CARD,
                          highlightthickness=1, highlightbackground=WARNING)
        b_card.grid(row=1, column=0, sticky="nsew")
        b_card.rowconfigure(1, weight=1)
        b_card.columnconfigure(0, weight=1)

        b_hdr = tk.Frame(b_card, bg=BG_PANEL, height=34)
        b_hdr.grid(row=0, column=0, sticky="ew")
        b_hdr.pack_propagate(False)
        self.blocked_count_lbl = tk.Label(b_hdr, text="    Blocked IPs  (0)",
                                           font=FONT_SUB, fg=WARNING, bg=BG_PANEL)
        self.blocked_count_lbl.pack(side="left", padx=10, pady=7)

        self.blocked_box = tk.Listbox(
            b_card, bg=BG_TABLE, fg=SEV_HIGH, font=FONT_MONO,
            relief="flat", bd=0, selectbackground="#2d1a1a",
            selectforeground=DANGER, activestyle="none",
            highlightthickness=0)
        self.blocked_box.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)

    # ── Helpers ────────────────────────────────────────────
    def _btn(self, parent, text, cmd, color, state="normal"):
        return tk.Button(
            parent, text=text, font=FONT_MONO,
            bg=BG_DARK, fg=color,
            activebackground=color, activeforeground=BG_DARK,
            relief="flat", bd=0, cursor="hand2",
            highlightthickness=1, highlightbackground=color,
            padx=10, pady=4, state=state, command=cmd)

    def _small_btn(self, parent, text, cmd, color):
        return tk.Button(
            parent, text=text, font=FONT_SMALL,
            bg=BG_PANEL, fg=color,
            activebackground=BORDER, activeforeground=TEXT_MAIN,
            relief="flat", bd=0, cursor="hand2",
            highlightthickness=1, highlightbackground=BORDER,
            padx=6, pady=2, command=cmd)

    def _now(self):
        return datetime.datetime.now().strftime("%H:%M:%S")

    def _update_clock(self):
        self.clock_lbl.config(
            text=datetime.datetime.now().strftime("⏱  %Y-%m-%d   %H:%M:%S"))
        self.after(1000, self._update_clock)

    def _log(self, msg, level="high"):
        self.alert_box.configure(state="normal")
        self.alert_box.insert("end", msg + "\n", level)
        self.alert_box.see("end")
        self.alert_box.configure(state="disabled")

    def _clear_alerts(self):
        self.alert_box.configure(state="normal")
        self.alert_box.delete("1.0", "end")
        self.alert_box.configure(state="disabled")

    def _on_mode_change(self):
    
        if self.live_mode.get() == "live":
            self.mode_dot.config(fg=SUCCESS, text="● LIVE")
        else:
            self.mode_dot.config(fg=ACCENT, text="● SIM")

    # ── Start / Stop ───────────────────────────────────────
    def _start(self):
        mode = self.live_mode.get()

        if mode == "live" and not SCAPY_AVAILABLE:
            messagebox.showerror("scapy not found",
                                  "Install scapy first:\n\npip install scapy")
            return

        if mode == "live":
            # تحقق من الصلاحيات (Linux/Mac)
            if os.name != "nt" and os.geteuid() != 0:
                if not messagebox.askyesno(
                    "Root Required",
                    "Live capture needs root/admin privileges.\n"
                    "Run with sudo, or continue anyway?"):
                    return

        self.monitoring = True
        self.total_pkts = 0
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        label = "🌐 LIVE capture" if mode == "live" else " Simulation"
        self._log(f"[{self._now()}]  ◉ {label} started…", "success")

        if mode == "live":
            threading.Thread(target=self._live_capture, daemon=True).start()
        else:
            threading.Thread(target=self._simulate,     daemon=True).start()

    def _stop(self):
        self.monitoring = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self._log(f"[{self._now()}]  ◉ Monitoring stopped.", "dim")

    # ── Simulation mode ────────────────────────────────────
    def _simulate(self):
        while self.monitoring:
            src  = random.choice(FAKE_IPS)
            port = random.choice(PORTS)
            if src not in self.detector.blocked_ips:
                self.detector.process_packet({"ip": src, "port": port})
                self.ip_hits[src] += 1
            time.sleep(random.uniform(0.3, 0.9))

    # ── Live capture mode (scapy) ──────────────────────────
    def _live_capture(self):
        
        def handle(pkt):
            if not self.monitoring:
                return
            if not pkt.haslayer(IP):
                return

            src  = pkt[IP].src
            dst  = pkt[IP].dst
            port = None
            proto = "OTHER"

            if pkt.haslayer(TCP):
                port  = pkt[TCP].dport
                proto = "TCP"
            elif pkt.haslayer(UDP):
                port  = pkt[UDP].dport
                proto = "UDP"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            
            if src in self.detector.blocked_ips:
                return

            self.total_pkts += 1
            self.detector.process_packet({"ip": src, "port": port})

            
            self.after(0, self.pkt_count_lbl.config,
                       {"text": f"📦 Packets: {self.total_pkts}"})

            
            if self.total_pkts % 50 == 0:
                msg = (f"[{self._now()}]   {self.total_pkts} packets "
                       f"captured  |  last: {src} → {dst}  [{proto}]")
                self.after(0, self._log, msg, "info")

        try:
            # sniff بدون stop_filter — يتوقف عند self.monitoring == False
            sniff(prn=handle, store=False,
                  stop_filter=lambda _: not self.monitoring)
        except Exception as e:
            self.after(0, self._log,
                       f"[{self._now()}]  ✖ Capture error: {e}", "high")
            self.after(0, self._stop)

    # ── Attack callback ────────────────────────────────────
    def _on_attack(self, attack_type, ip, severity, count=0):
        now   = self._now()
        icon  = "" if severity == "HIGH" else ""
        msg   = f"[{now}]  {icon} {attack_type}  |  {ip}  |  {severity}"
        level = "high" if severity == "HIGH" else "medium"
        self.after(0, self._log, msg, level)
        self.after(0, self._refresh_table)

    # ── Table ──────────────────────────────────────────────
    def _refresh_table(self):
        for r in self.hist_tree.get_children():
            self.hist_tree.delete(r)
        attacks = self.detector.database.get_recent_attacks(limit=500)
        for a in attacks:
            sev = a["severity"]
            tag = sev if sev in ("HIGH", "MEDIUM", "LOW") else ""
            self.hist_tree.insert("", "end",
                                   values=(a["id"], a["date"], a["time"],
                                           a["day"], a["ip"],
                                           a["attack_type"], a["severity"]),
                                   tags=(tag,))
        total = self.detector.database.get_total_count()
        self.db_count_lbl.config(text=f"Total records: {total}")

    # ── Block / Unblock ────────────────────────────────────
    def _block_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Alert", "Enter an IP address first")
            return
        self.detector.blocked_ips.add(ip)
        self._sync_blocked_box()
        self._log(f"[{self._now()}]   Blocked: {ip}", "medium")
        self.ip_entry.delete(0, "end")

    def _unblock_ip(self):
        sel = self.blocked_box.curselection()
        if not sel:
            messagebox.showwarning("Alert", "Select an IP from the list first")
            return
        ip = self.blocked_box.get(sel[0])
        self.detector.blocked_ips.discard(ip)
        self._sync_blocked_box()
        self._log(f"[{self._now()}]  ✔ Unblocked: {ip}", "success")

    def _sync_blocked_box(self):
        self.blocked_box.delete(0, "end")
        for ip in sorted(self.detector.blocked_ips):
            self.blocked_box.insert("end", ip)
        count = len(self.detector.blocked_ips)
        self.blocked_count_lbl.config(text=f"    Blocked IPs  ({count})")

    # ── Clear DB ───────────────────────────────────────────
    def _clear_db(self):
        if messagebox.askyesno("Confirm", "Delete ALL records from the database?\nThis cannot be undone."):
            self.detector.database.clear_all()
            self._refresh_table()
            self._log(f"[{self._now()}]  🗑 Database cleared.", "dim")

    # ── Export CSV ─────────────────────────────────────────
    def _export_csv(self):
        attacks = self.detector.database.get_recent_attacks(limit=5000)
        if not attacks:
            messagebox.showinfo("Export", "No records to export.")
            return
        filename = f"attacks_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(os.path.expanduser("~"), filename)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["id","date","time","day","ip","attack_type","severity"])
            writer.writeheader()
            writer.writerows(attacks)
        self._log(f"[{self._now()}]  💾 Exported: {filename}", "success")
        messagebox.showinfo("Export Complete", f"Saved to:\n{filepath}")


if __name__ == "__main__":
    SNIDS_App().mainloop()
