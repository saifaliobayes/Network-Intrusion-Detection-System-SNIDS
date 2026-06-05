# SNIDS: Smart Network Intrusion Detection System 🛡️🌐

SNIDS is a comprehensive, desktop-based Network Intrusion Detection System built with Python. It features a modern dark-themed graphical user interface (GUI) to monitor network traffic in real-time, log persistent threat history using SQLite, and detect potential network attacks like Flooding and Port Scanning.

---

### 🚀 Key Features

- **Dual-Mode Traffic Monitoring:**
  - **Simulation Mode:** Generates safe, random network traffic for testing and analytical demonstration.
  - **Live Capture Mode:** Sniffs real-time packet streams directly from the network using `Scapy`.
- **Intelligent Threat Detection:**
  - **Flood Attack Detection:** Identifies traffic volume anomalies from a single source IP.
  - **Port Scan Detection:** Detects suspicious scanning behavior across multiple destination ports.
- **Advanced Security Controls:**
  - Allows network administrators to manually **Block** or **Unblock** specific IP addresses instantly.
- **Robust Data Logging & Management:**
  - Integrated with an asynchronous **SQLite database** layer to log detailed attack timelines (Date, Time, Day, IP, Attack Type, and Severity).
  - Built-in capabilities to **Export security logs into a CSV file** directly to the user's home folder.
  - Options to dynamically clear the persistent data footprint.

---

### 🛠️ Tech Stack & Dependencies

- **Language:** Python 3.x
- **GUI Framework:** Tkinter (with customized elegant dark stylesheets)
- **Packet Engineering:** Scapy (Required for Live Mode)
- **Database Engine:** SQLite3 (Self-initializing on launch)

---

### ⚙️ Installation & Setup Guide

> ⚠️ **Prerequisite Notes:**
> 1. Running live network packet capturing typically requires administrative or root privileges.
> 2. On Windows, ensure you have **Npcap** or **WinPcap** installed for Scapy to sniff raw hardware lines.

---

### 👥 Contributors & Team Members

This project was developed as a collaborative academic group effort by a team of 3 students with equally distributed responsibilities:

1. **Saif Ali** (Lead Software Developer):
   - Designed and implemented the complete backend logic for network packet sniffing and anomaly detection algorithms (`detector.py`).
   - Developed the secure standalone SQL data persistence layer and asynchronous logging capabilities (`database.py`).
   - Designed and engineered the custom dark-themed graphical user interface (GUI) and tied front-end components to system events (`main.py`).

2. **[Second Member]: (Network Security Analyst & Quality Assurance):
   - Researched network threat signatures, attack behaviors, and defined optimal detection volume thresholds.
   - Performed continuous system validation, penetration testing, and simulated multi-source Flood and Port Scan attacks.
   - Responsible for setting up the local testing environment and generating network simulation datasets.

3. **[Third Member]: (System Architecture & Technical Documentation):
   - Documented the system requirements, functional specifications, and managed the technical project reporting.
   - Designed the conceptual architecture, operational flowcharts, and network traffic processing diagrams.
   - Managed the comprehensive academic presentation material and prepared the engineering defense guidelines.

To get a local copy up and running, execute these commands inside your terminal:

```bash
# 1. Clone this repository
git clone https://github.com/saifaliobayes/Network-Intrusion-Detection-System-SNIDS.git

# 2. Navigate into the project folder
cd Network-Intrusion-Detection-System-SNIDS

# 3. Install required network packets architecture
pip install scapy

# 4. Launch the application (Run as Administrator / with sudo on Linux)
python main.py
```
