import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

class NetworkSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CodeAlpha - Network Packet Sniffer")
        self.root.geometry("920x620")
        self.root.minsize(750, 500)

        self.sniffing = False
        self.all_records = []  # Stores (packet, row_data)

        self._apply_theme()
        self._build_widgets()

    def _apply_theme(self):
        self.bg_color = "#1e1e2e"
        self.card_color = "#24273a"
        self.accent_color = "#89b4fa"

        self.root.configure(bg=self.bg_color)
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background="#181825",
            foreground="#cdd6f4",
            fieldbackground="#181825",
            rowheight=26,
            font=("Consolas", 10)
        )
        style.map("Treeview", background=[("selected", "#313244")], foreground=[("selected", "#89b4fa")])
        style.configure(
            "Treeview.Heading",
            background="#313244",
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold")
        )

    def _build_widgets(self):
        # Top Header & Controls
        control_frame = tk.Frame(self.root, bg=self.card_color, padx=12, pady=10)
        control_frame.pack(fill="x", padx=10, pady=8)

        tk.Label(
            control_frame, 
            text="Packet Sniffer Dashboard", 
            font=("Segoe UI", 13, "bold"), 
            bg=self.card_color, 
            fg=self.accent_color
        ).pack(side="left", padx=5)

        # Protocol Filter Dropdown
        tk.Label(control_frame, text="Filter:", font=("Segoe UI", 10), bg=self.card_color, fg="#cdd6f4").pack(side="left", padx=(20, 5))
        self.filter_var = tk.StringVar(value="ALL")
        self.filter_menu = ttk.Combobox(
            control_frame, 
            textvariable=self.filter_var, 
            values=["ALL", "TCP", "UDP", "ICMP"], 
            state="readonly", 
            width=8
        )
        self.filter_menu.pack(side="left", padx=5)
        # Bind change event taaki dropdown badalte hi table refresh ho jaye
        self.filter_menu.bind("<<ComboboxSelected>>", self.apply_filter)

        # Buttons
        self.btn_clear = tk.Button(control_frame, text="Clear", bg="#45475a", fg="#ffffff", relief="flat", font=("Segoe UI", 9, "bold"), padx=12, command=self.clear_table)
        self.btn_clear.pack(side="right", padx=5)

        self.btn_stop = tk.Button(control_frame, text="Stop", bg="#f38ba8", fg="#11111b", relief="flat", font=("Segoe UI", 9, "bold"), padx=14, state="disabled", command=self.stop_sniffing)
        self.btn_stop.pack(side="right", padx=5)

        self.btn_start = tk.Button(control_frame, text="Start Sniffing", bg="#a6e3a1", fg="#11111b", relief="flat", font=("Segoe UI", 9, "bold"), padx=14, command=self.start_sniffing)
        self.btn_start.pack(side="right", padx=5)

        # Packet Table
        table_frame = tk.Frame(self.root, bg=self.bg_color)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 5))

        columns = ("No", "Source IP", "Destination IP", "Protocol", "Info")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("No", text="#")
        self.tree.heading("Source IP", text="Source IP")
        self.tree.heading("Destination IP", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Info", text="Info")

        self.tree.column("No", width=50, anchor="center")
        self.tree.column("Source IP", width=150, anchor="center")
        self.tree.column("Destination IP", width=150, anchor="center")
        self.tree.column("Protocol", width=90, anchor="center")
        self.tree.column("Info", width=380, anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # Details Pane
        detail_frame = tk.LabelFrame(self.root, text=" Packet Inspector & Payload ", bg=self.card_color, fg=self.accent_color, font=("Segoe UI", 10, "bold"), padx=8, pady=6)
        detail_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=6, bg="#11111b", fg="#a6adc8", font=("Consolas", 9), relief="flat")
        self.detail_text.pack(fill="both", expand=True)

        # Status Bar
        self.status_var = tk.StringVar(value="Status: Ready | Total Packets: 0 | Displayed: 0")
        status_bar = tk.Label(self.root, textvariable=self.status_var, font=("Segoe UI", 9), bg="#11111b", fg="#a6adc8", anchor="w", padx=10, pady=3)
        status_bar.pack(fill="x", side="bottom")

    def packet_handler(self, packet):
        if not self.sniffing:
            return

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            proto_name = "Other"
            info = ""

            if proto == 6 and TCP in packet:
                proto_name = "TCP"
                info = f"Port: {packet[TCP].sport} -> {packet[TCP].dport} | Flags: {packet[TCP].flags}"
            elif proto == 17 and UDP in packet:
                proto_name = "UDP"
                info = f"Port: {packet[UDP].sport} -> {packet[UDP].dport} | Length: {packet[UDP].len}"
            elif proto == 1 or ICMP in packet:
                proto_name = "ICMP"
                info = f"Type: {packet[ICMP].type} | Code: {packet[ICMP].code}"

            total_id = len(self.all_records) + 1
            record = (packet, (total_id, src, dst, proto_name, info))
            self.all_records.append(record)

            # Check if it matches current filter
            current_filter = self.filter_var.get()
            if current_filter == "ALL" or proto_name == current_filter:
                self.root.after(0, self._insert_row, total_id, src, dst, proto_name, info)

    def _insert_row(self, count, src, dst, proto, info):
        self.tree.insert("", "end", values=(count, src, dst, proto, info))
        self.status_var.set(f"Status: Sniffing active... | Total Captured: {len(self.all_records)} | Showing: {len(self.tree.get_children())}")
        self.tree.yview_moveto(1)

    def apply_filter(self, event=None):
        selected_filter = self.filter_var.get()
        self.tree.delete(*self.tree.get_children())
        self.detail_text.delete("1.0", tk.END)

        for _, row_data in self.all_records:
            proto_name = row_data[3]
            if selected_filter == "ALL" or proto_name == selected_filter:
                self.tree.insert("", "end", values=row_data)

        status_text = "Sniffing active..." if self.sniffing else "Stopped"
        self.status_var.set(f"Status: {status_text} | Total Captured: {len(self.all_records)} | Showing: {len(self.tree.get_children())}")

    def on_packet_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        packet_num = int(item["values"][0])

        packet = self.all_records[packet_num - 1][0]
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, f"[+] Summary: {packet.summary()}\n\n")

        if Raw in packet:
            raw_data = packet[Raw].load
            self.detail_text.insert(tk.END, f"[+] Raw Payload ({len(raw_data)} bytes):\n{raw_data}\n")
        else:
            self.detail_text.insert(tk.END, "[*] No application layer raw payload present.")

    def start_sniffing(self):
        self.sniffing = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status_var.set("Status: Sniffing active...")

        self.sniff_thread = threading.Thread(target=self._sniff_worker, daemon=True)
        self.sniff_thread.start()

    def _sniff_worker(self):
        sniff(prn=self.packet_handler, stop_filter=lambda x: not self.sniffing, store=False)

    def stop_sniffing(self):
        self.sniffing = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_var.set(f"Status: Stopped | Total Captured: {len(self.all_records)} | Showing: {len(self.tree.get_children())}")

    def clear_table(self):
        self.tree.delete(*self.tree.get_children())
        self.all_records.clear()
        self.detail_text.delete("1.0", tk.END)
        self.status_var.set("Status: Ready | Total Captured: 0 | Showing: 0")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSnifferGUI(root)
    root.mainloop()
