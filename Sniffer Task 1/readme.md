# CodeAlpha - Network Packet Sniffer (Task 1)

A feature-rich Network Packet Sniffer built in Python using **Scapy** and **Tkinter**. This tool captures live network packets, extracts protocol information (IP, TCP, UDP, ICMP), decodes raw payloads, and provides a dynamic graphical user interface (GUI) with real-time protocol filtering.

---

## 📌 Features

- **Live Packet Capture:** Captures incoming and outgoing network traffic in real time.
- **Protocol Inspection:** Identifies protocols including TCP, UDP, ICMP, and others, extracting source/destination IP addresses, port numbers, flags, and packet length.
- **Dynamic Protocol Filtering:** Instant switching between `ALL`, `TCP`, `UDP`, and `ICMP` packets without losing historical capture data.
- **Deep Packet Inspector & Payload Viewer:** Click any captured packet to view its detailed Scapy summary and raw hex/byte payload.
- **Non-blocking Architecture:** Utilizes Python's `threading` module to ensure UI responsiveness during packet sniffing operations.
- **Modern Dark UI:** Clean dark theme designed for security analysis.

---

## 🛠️ Prerequisites & Requirements

- **Operating System:** Linux (Kali Linux, Ubuntu, Debian) or Windows / macOS
- **Python Version:** Python 3.8+
- **Administrative Privileges:** Root/Administrator access is required to open raw network sockets.

### Dependencies

Install the required Python packages:

```bash
pip install scapy
```

*Note on Linux:* Tkinter is usually pre-installed. If missing, install it via:
```bash
sudo apt update && sudo apt install python3-tk -y
```

---

## 🚀 How to Run

### 1. Clone the Repository
```bash
gitclone https://github.com/root-vector-io/Cyber-Security-Projects.git
cd CodeAlpha_Network_Sniffer
```

### 2. Run the Application
Raw socket packet capturing requires superuser privileges:

#### On Linux (Kali Linux / Ubuntu):
```bash
sudo python3 sniffer_gui.py
```
*(Kali password is usually 'your kali pass' )*

#### On Windows:
Open PowerShell or Command Prompt as **Administrator** and run:
```bash
python sniffer_gui.py
```
*(Ensure Npcap is installed with "WinPcap API Compatibility" enabled)*

---

## 🖥️ Usage Guide

1. Click **Start Sniffing** to initiate packet capture.
2. Generate network traffic by browsing websites or opening a terminal and running:
   ```bash
   ping -c 4 8.8.8.8
   ```
3. Use the **Filter** dropdown to display specific protocols (`TCP`, `UDP`, or `ICMP`).
4. Click on any row in the table to view the raw packet data and payload in the **Packet Inspector** pane.
5. Click **Stop** to halt sniffing or **Clear** to reset the captured records.

---

## 📸 Screenshots & Output Analysis

### GUI Dashboard
![Dashboard Preview](screenshot.png)

### Output Explanation
* **DNS Resolution (UDP Port 53):** Displays query exchanges between the local machine and the DNS resolver.
* **Secure Web Traffic (TCP Port 443):** Captures TLS handshake records (`Client Hello`, `Server Hello`) and encrypted payloads.
* **Network Diagnostics (ICMP):** Displays Echo Request and Echo Reply packets generated during connectivity testing (`ping`).

---

## ⚠️ Disclaimer

This tool is created for educational and academic purposes as part of the CodeAlpha Cybersecurity Internship Program. Capturing network traffic on networks without proper authorization is strictly illegal. Use this program only on networks you own or have explicit permission to audit.
