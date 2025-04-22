import customtkinter as ctk         # Modern GUI with customizable widgets
import tkinter as tk               # Compatibility with customtkinter
from tkinter import messagebox, filedialog, ttk  # Dialogs and themed widgets
import threading                   # Run scans in a separate thread
from concurrent.futures import ThreadPoolExecutor  # Concurrent execution
import queue                       # Communication between threads
import socket                      # Port scanning
import subprocess                  # Pinging hosts
import ipaddress                   # Subnet validation
import json                        # Save results in JSON format
import csv                         # Save results in CSV format
import platform                    # Detect operating system
from datetime import datetime      # Timestamp scan history

# Set customtkinter appearance for a dark, neon-green theme
ctk.set_appearance_mode("dark")    # Dark theme for hacker aesthetic
ctk.set_default_color_theme("green")  # Neon green accents

# Simplified tooltip class for user guidance
class ToolTip:
    """Provides hover tooltips for widgets to guide user input."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        print(f"Tooltip created for widget: {widget}, text: {text}")  # Debug
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        """Display the tooltip window near the widget."""
        print(f"Showing tooltip: {self.text}")  # Debug
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)
        self.tip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self.tip_window,
            text=self.text,
            background="#333333",
            foreground="white",
            relief="solid",
            borderwidth=1,
            font=("Courier", 10),
            padx=5,
            pady=3
        )
        label.pack()
        self.tip_window.lift()  # Ensure tooltip is on top
        self.tip_window.update_idletasks()  # Ensure tooltip renders

    def hide_tip(self, event=None):
        """Hide the tooltip window."""
        print(f"Hiding tooltip: {self.text}")  # Debug
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

# NetworkScanner class for scanning logic
class NetworkScanner:
    """Handles network scanning operations, including pinging IPs and checking ports."""
    def __init__(self):
        """Initialize scanner with thread-safe storage for live hosts."""
        self.live_hosts = []  # Store live host information
        self.hosts_lock = threading.Lock()  # Ensure thread-safe access
        self.cancel_flag = False  # Flag for scan cancellation

    def validate_subnet(self, subnet):
        """Validate subnet format (e.g., '192.168.0.0/24')."""
        try:
            ipaddress.ip_network(subnet, strict=False)
            return True
        except ValueError:
            return False

    def parse_ports(self, port_string):
        """Parse port string (e.g., '21,22,80-100') into a list of integers."""
        ports = []
        try:
            for part in port_string.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
            return ports
        except ValueError:
            return []

    def ping_ip(self, ip, queue):
        """Ping an IP to check if live and guess OS based on TTL."""
        if self.cancel_flag:
            return
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            queue.put({"type": "log", "data": f"Pinging {ip}..."})
            output = subprocess.check_output(['ping', param, '1', ip], universal_newlines=True, timeout=1)
            ttl = int(output.lower().split("ttl=")[1].split()[0])
            os_guess = "Windows" if ttl > 64 else "Linux/Unix"
            with self.hosts_lock:
                self.live_hosts.append({'ip': ip, 'os': os_guess, 'open_ports': []})
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass  # Host is not live

    def check_ports(self, ip, ports, timeout, queue):
        """Check specified ports on an IP for openness."""
        if self.cancel_flag:
            return []
        open_ports = []
        for port in ports:
            if self.cancel_flag:
                break
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            queue.put({"type": "log", "data": f"Scanning port {port} on {ip}..."})
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = "Unknown"
                open_ports.append({'port': port, 'service': service, 'status': 'Open'})
                queue.put({"type": "log", "data": f"Port {port} ({service}) open on {ip}"})
            sock.close()
        return open_ports

    def scan_network(self, subnet, ports, timeout, queue):
        """Scan network by pinging IPs and checking ports on live hosts."""
        self.live_hosts = []
        self.cancel_flag = False
        ping_counter = 0
        lock = threading.Lock()

        def ping_host(ip):
            nonlocal ping_counter
            if self.cancel_flag:
                return
            self.ping_ip(ip, queue)
            with lock:
                ping_counter += 1
                queue.put({"type": "ping_progress", "data": ping_counter})

        queue.put({"type": "status", "data": "Starting host discovery..."})
        with ThreadPoolExecutor(max_workers=50) as executor:
            ip_list = [f"{subnet}.{i}" for i in range(1, 255)]
            executor.map(ping_host, ip_list)

        if self.cancel_flag:
            queue.put({"type": "status", "data": "Scan cancelled"})
            queue.put({"type": "scan_complete"})
            return

        queue.put({"type": "port_total", "data": len(self.live_hosts)})

        port_counter = 0

        def scan_host(host):
            nonlocal port_counter
            if self.cancel_flag:
                return
            open_ports = self.check_ports(host['ip'], ports, timeout, queue)
            host['open_ports'] = open_ports
            with lock:
                port_counter += 1
                queue.put({"type": "port_progress", "data": port_counter})
                queue.put({"type": "result", "data": host})

        queue.put({"type": "status", "data": "Scanning ports on live hosts..."})
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(scan_host, self.live_hosts)

        if self.cancel_flag:
            queue.put({"type": "status", "data": "Scan cancelled"})
        else:
            queue.put({"type": "status", "data": "Scan completed"})
        queue.put({"type": "scan_complete"})

    def save_results(self, filename, format):
        """Save scan results to JSON or CSV file."""
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.live_hosts, f, indent=4)
        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "OS", "Open Ports"])
                for host in self.live_hosts:
                    ports = ", ".join([f"{p['port']} ({p['service']})" for p in host['open_ports']])
                    writer.writerow([host['ip'], host.get('os', 'Unknown'), ports])

# ScannerGUI class for the graphical interface
class ScannerGUI(ctk.CTk):
    """Main GUI class for the CyberPulse Network Scanner, providing a user-friendly
    interface for network scanning, results display, and history management."""
    def __init__(self):
        """Initialize the GUI with a dark, hacker-inspired layout and all widgets."""
        super().__init__()
        self.title("Network Scanner - CyberPulse")
        self.geometry("1000x750")  # Optimized size for all widgets
        self.minsize(900, 600)  # Minimum size for resizing
        self.resizable(True, True)  # Allow window resizing
        self.scanning = False  # Track scan status
        self.scan_history = []  # Store scan history
        self.current_results = []  # Store current results

        # Configure main grid: column 1 expands, row 5 for results table
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(5, weight=1)

        # Sidebar for scan history
        self.sidebar_frame = ctk.CTkFrame(self, width=200, border_width=1, border_color="gray")
        self.sidebar_frame.grid(row=0, column=0, rowspan=7, padx=10, pady=5, sticky="nsw")
        self.sidebar_frame.grid_rowconfigure(1, weight=1)
        print("Sidebar frame created")  # Debug

        self.history_label = ctk.CTkLabel(
            self.sidebar_frame, text="Scan History", font=("Courier", 14, "bold")
        )
        self.history_label.grid(row=0, column=0, padx=5, pady=5)

        self.history_list = ctk.CTkScrollableFrame(self.sidebar_frame)
        self.history_list.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Title label
        self.title_label = ctk.CTkLabel(
            self, text="CyberPulse Network Scanner", font=("Courier", 24, "bold")
        )
        self.title_label.grid(row=0, column=1, pady=5)
        print("Title label created")  # Debug

        # Input frame for subnet, ports, and timeout
        self.input_frame = ctk.CTkFrame(self, border_width=1, border_color="gray")
        self.input_frame.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        self.input_frame.grid_columnconfigure(1, weight=1)
        print("Input frame created")  # Debug

        # Subnet input with tooltip and error label
        self.subnet_label = ctk.CTkLabel(
            self.input_frame, text="Subnet (e.g., 192.168.0):", font=("Courier", 13)
        )
        self.subnet_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.subnet_entry = ctk.CTkEntry(self.input_frame, font=("Courier", 12), placeholder_text="e.g., 192.168.0")
        self.subnet_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.subnet_error = ctk.CTkLabel(self.input_frame, text="", font=("Courier", 10), text_color="red")
        self.subnet_error.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        ToolTip(self.subnet_entry, "Enter the network base (e.g., 192.168.0 for 192.168.0.0/24)")

        # Ports input with checkboxes and custom entry
        self.ports_label = ctk.CTkLabel(
            self.input_frame, text="Ports:", font=("Courier", 13)
        )
        self.ports_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.ports_frame = ctk.CTkFrame(self.input_frame)
        self.ports_frame.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.ports_frame.grid_columnconfigure(0, weight=1)
        print("Ports frame created")  # Debug

        self.port_vars = {
            21: ctk.BooleanVar(value=True),
            22: ctk.BooleanVar(value=True),
            80: ctk.BooleanVar(value=True),
            443: ctk.BooleanVar(value=True)
        }
        self.port_checkboxes = {}
        for idx, port in enumerate(self.port_vars):
            self.port_checkboxes[port] = ctk.CTkCheckBox(
                self.ports_frame, text=f"Port {port}", variable=self.port_vars[port], font=("Courier", 12)
            )
            self.port_checkboxes[port].grid(row=0, column=idx, padx=5, sticky="w")

        self.custom_ports_label = ctk.CTkLabel(
            self.ports_frame, text="Custom Ports:", font=("Courier", 12)
        )
        self.custom_ports_label.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        self.custom_ports_entry = ctk.CTkEntry(self.ports_frame, font=("Courier", 12), placeholder_text="e.g., 8080,1000-2000")
        self.custom_ports_entry.grid(row=1, column=2, columnspan=2, padx=5, pady=5, sticky="ew")
        self.ports_error = ctk.CTkLabel(self.ports_frame, text="", font=("Courier", 10), text_color="red")
        self.ports_error.grid(row=2, column=0, columnspan=4, padx=5, pady=5, sticky="w")
        ToolTip(self.custom_ports_entry, "Enter additional ports or ranges (e.g., 8080,1000-2000)")

        # Timeout input with tooltip and error label
        self.timeout_label = ctk.CTkLabel(
            self.input_frame, text="Timeout (seconds):", font=("Courier", 13)
        )
        self.timeout_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.timeout_entry = ctk.CTkEntry(self.input_frame, font=("Courier", 12), placeholder_text="e.g., 1.0")
        self.timeout_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.timeout_entry.insert(0, "1.0")
        self.timeout_error = ctk.CTkLabel(self.input_frame, text="", font=("Courier", 10), text_color="red")
        self.timeout_error.grid(row=2, column=2, padx=5, pady=5, sticky="w")
        ToolTip(self.timeout_entry, "Set the timeout for each port check in seconds (e.g., 1.0)")

        # Start and Cancel buttons
        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.grid(row=2, column=1, pady=5)
        self.start_button = ctk.CTkButton(
            self.button_frame, text="Initiate Scan", command=self.start_scan, font=("Courier", 14, "bold")
        )
        self.start_button.grid(row=0, column=0, padx=5)
        self.cancel_button = ctk.CTkButton(
            self.button_frame, text="Cancel Scan", command=self.cancel_scan, font=("Courier", 14, "bold"), fg_color="red"
        )
        self.cancel_button.grid(row=0, column=1, padx=5)
        self.cancel_button.configure(state="disabled")
        print("Start and cancel buttons created")  # Debug

        # Status label for scan feedback
        self.status_label = ctk.CTkLabel(
            self, text="Ready", font=("Courier", 13, "italic")
        )
        self.status_label.grid(row=3, column=1, pady=5)
        print("Status label created")  # Debug

        # Container for side-by-side logs and progress bars
        # Layout optimizes horizontal space, with logs taking more width for readability
        self.status_container = ctk.CTkFrame(self, fg_color="#2a2a2a", border_width=1, border_color="gray")
        self.status_container.grid(row=4, column=1, padx=10, pady=5, sticky="ew")
        self.status_container.grid_columnconfigure(0, weight=3)  # Logs get more space
        self.status_container.grid_columnconfigure(1, weight=2)  # Progress bars are compact
        print("Status container created")  # Debug

        # Scan logs frame
        self.log_frame = ctk.CTkFrame(self.status_container, border_width=1, border_color="gray")
        self.log_frame.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="nsew")
        self.log_frame.grid_columnconfigure(0, weight=1)
        self.log_label = ctk.CTkLabel(
            self.log_frame, text="Scan Logs", font=("Courier", 13)
        )
        self.log_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.log_text = ctk.CTkTextbox(
            self.log_frame, height=80, font=("Courier", 10), fg_color="#1a1a1a", text_color="green"
        )
        self.log_text.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        self.log_text.configure(state="disabled")
        print("Log frame created")  # Debug

        # Progress bars for host discovery and port scanning
        self.progress_frame = ctk.CTkFrame(self.status_container, border_width=1, border_color="gray")
        self.progress_frame.grid(row=0, column=1, padx=(10, 0), pady=5, sticky="nsew")
        self.progress_frame.grid_columnconfigure(0, weight=1)
        self.ping_progress_label = ctk.CTkLabel(
            self.progress_frame, text="Host Discovery: 0%", font=("Courier", 13)
        )
        self.ping_progress_label.grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.ping_progress = ctk.CTkProgressBar(self.progress_frame)
        self.ping_progress.grid(row=1, column=0, padx=5, pady=2, sticky="ew")
        self.ping_progress.set(0)
        self.port_progress_label = ctk.CTkLabel(
            self.progress_frame, text="Port Scanning: 0%", font=("Courier", 13)
        )
        self.port_progress_label.grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.port_progress = ctk.CTkProgressBar(self.progress_frame)
        self.progress_frame.grid_rowconfigure(3, weight=1)
        self.port_progress.grid(row=3, column=0, padx=5, pady=2, sticky="ew")
        self.port_progress.set(0)
        print("Progress frame created")  # Debug

        # Results table with scrollable Treeview
        self.results_frame = ctk.CTkFrame(self, border_width=1, border_color="gray")
        self.results_frame.grid(row=5, column=1, padx=10, pady=5, sticky="nsew")
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.results_frame.grid_rowconfigure(0, weight=1)
        self.results_tree = ttk.Treeview(
            self.results_frame,
            columns=("IP", "OS", "Ports"),
            show="headings",
            style="Treeview"
        )
        self.results_tree.heading("IP", text="IP Address")
        self.results_tree.heading("OS", text="OS")
        self.results_tree.heading("Ports", text="Open Ports")
        self.results_tree.column("IP", width=150)
        self.results_tree.column("OS", width=100)
        self.results_tree.column("Ports", width=350)  # Wider for readability
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        self.scrollbar = ctk.CTkScrollbar(
            self.results_frame, orientation="vertical", command=self.results_tree.yview
        )
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.results_tree.configure(yscrollcommand=self.scrollbar.set)
        print("Results frame and Treeview created")  # Debug

        # Save frame for exporting results
        self.save_frame = ctk.CTkFrame(self, border_width=1, border_color="gray")
        self.save_frame.grid(row=6, column=1, padx=10, pady=(5, 10), sticky="ew")
        self.save_frame.grid_columnconfigure(0, weight=1)
        self.format_var = ctk.StringVar(value="json")
        self.format_combobox = ctk.CTkComboBox(
            self.save_frame, values=["json", "csv"], variable=self.format_var, font=("Courier", 12)
        )
        self.format_combobox.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.save_button = ctk.CTkButton(
            self.save_frame, text="Save Results", command=self.save_results, font=("Courier", 12)
        )
        self.save_button.grid(row=0, column=1, padx=10, pady=5, sticky="e")
        self.save_button.configure(state="disabled")
        print("Save frame and button created")  # Debug

        # Initialize scanner and queue for GUI updates
        self.queue = queue.Queue()
        self.scanner = NetworkScanner()
        self.port_total = 0  # Track live hosts for port scanning progress

        # Customize Treeview style for dark theme
        style = ttk.Style()
        style.configure(
            "Treeview",
            background="#2b2b2b",
            foreground="white",
            fieldbackground="#2b2b2b",
            font=("Courier", 10)
        )
        style.configure("Treeview.Heading", font=("Courier", 10, "bold"))

        self.after(100, self.process_queue)

    def show_error(self, field, message):
        """Display error messages for input validation."""
        error_labels = {
            "subnet": self.subnet_error,
            "ports": self.ports_error,
            "timeout": self.timeout_error
        }
        if field in error_labels:
            error_labels[field].configure(text=message)
        
        def clear_error(event, label):
            label.configure(text="")
        
        if field == "subnet":
            self.subnet_entry.bind("<Key>", lambda e: clear_error(e, self.subnet_error))
        elif field == "ports":
            self.custom_ports_entry.bind("<Key>", lambda e: clear_error(e, self.ports_error))
        elif field == "timeout":
            self.timeout_entry.bind("<Key>", lambda e: clear_error(e, self.timeout_error))

    def start_scan(self):
        """Start a network scan based on user inputs."""
        if self.scanning:
            messagebox.showinfo("Info", "Scan already in progress.")
            return
        self.scanning = True
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.results_tree.delete(*self.results_tree.get_children())
        self.current_results = []
        self.save_button.configure(state="disabled")
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

        subnet = self.subnet_entry.get()
        custom_ports_str = self.custom_ports_entry.get()
        try:
            timeout = float(self.timeout_entry.get())
        except ValueError:
            self.show_error("timeout", "Invalid timeout value.")
            self.scanning = False
            self.start_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            return
        if not self.scanner.validate_subnet(f"{subnet}.0/24"):
            self.show_error("subnet", "Invalid subnet format.")
            self.scanning = False
            self.start_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            return

        ports = [port for port, var in self.port_vars.items() if var.get()]
        if custom_ports_str:
            custom_ports = self.scanner.parse_ports(custom_ports_str)
            if not custom_ports and custom_ports_str:
                self.show_error("ports", "Invalid custom ports format.")
                self.scanning = False
                self.start_button.configure(state="normal")
                self.cancel_button.configure(state="disabled")
                return
            ports.extend(custom_ports)
        if not ports:
            self.show_error("ports", "No ports selected or entered.")
            self.scanning = False
            self.start_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            return

        self.ping_progress.set(0)
        self.port_progress.set(0)
        self.ping_progress_label.configure(text="Host Discovery: 0%")
        self.port_progress_label.configure(text="Port Scanning: 0%")
        self.status_label.configure(text="Initializing scan...")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history_entry = f"{timestamp}\nSubnet: {subnet}"
        self.scan_history.append({"entry": history_entry, "results": []})
        if len(self.scan_history) > 5:
            self.scan_history.pop(0)
        self.update_history_list()

        threading.Thread(
            target=self.scanner.scan_network,
            args=(subnet, ports, timeout, self.queue),
            daemon=True
        ).start()

    def cancel_scan(self):
        """Cancel an ongoing scan."""
        if not self.scanning:
            return
        self.scanner.cancel_flag = True
        self.scanning = False
        self.start_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self.status_label.configure(text="Cancelling scan...")

    def update_history_list(self):
        """Update the scan history sidebar with recent scans."""
        for widget in self.history_list.winfo_children():
            widget.destroy()
        for idx, entry in enumerate(self.scan_history):
            btn = ctk.CTkButton(
                self.history_list,
                text=entry["entry"],
                font=("Courier", 10),
                command=lambda i=idx: self.load_history(i),
                fg_color="#333333",
                hover_color="#555555"
            )
            btn.pack(fill="x", padx=5, pady=2)

    def load_history(self, index):
        """Load a previous scan's results into the table."""
        self.results_tree.delete(*self.results_tree.get_children())
        self.current_results = self.scan_history[index]["results"]
        for host in self.current_results:
            open_ports_str = ", ".join([f"{p['port']} ({p['service']})" for p in host['open_ports']])
            self.results_tree.insert(
                "", "end", values=(host['ip'], host.get('os', 'Unknown'), open_ports_str)
            )
        entry_line = self.scan_history[index]['entry'].split('\n')[0]
        host_count = len(self.scan_history[index]['results'])
        self.status_label.configure(
            text=f"Loaded scan from {entry_line} ({host_count} hosts)"
        )

    def process_queue(self):
        """Process queue messages to update GUI elements."""
        try:
            while True:
                message = self.queue.get_nowait()
                if message["type"] == "ping_progress":
                    progress = message["data"] / 254
                    self.ping_progress.set(progress)
                    self.ping_progress_label.configure(
                        text=f"Host Discovery: {int(progress * 100)}%"
                    )
                elif message["type"] == "port_total":
                    self.port_total = message["data"]
                    self.port_progress_label.configure(
                        text=f"Port Scanning: 0/{self.port_total}"
                    )
                elif message["type"] == "port_progress":
                    if self.port_total > 0:
                        progress = message["data"] / self.port_total
                        self.port_progress.set(progress)
                        self.port_progress_label.configure(
                            text=f"Port Scanning: {message['data']}/{self.port_total}"
                        )
                elif message["type"] == "result":
                    host = message["data"]
                    self.current_results.append(host)
                    if self.scan_history:
                        self.scan_history[-1]["results"] = self.current_results
                    open_ports_str = ", ".join([f"{p['port']} ({p['service']})" for p in host['open_ports']])
                    self.results_tree.insert(
                        "", "end", values=(host['ip'], host.get('os', 'Unknown'), open_ports_str)
                    )
                    self.save_button.configure(state="normal")
                elif message["type"] == "status":
                    self.status_label.configure(text=message["data"])
                elif message["type"] == "log":
                    self.log_text.configure(state="normal")
                    self.log_text.insert(tk.END, message["data"] + "\n")
                    self.log_text.see(tk.END)
                    self.log_text.configure(state="disabled")
                elif message["type"] == "scan_complete":
                    self.scanning = False
                    self.start_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    if self.scanner.cancel_flag:
                        self.status_label.configure(text="Scan cancelled")
                    else:
                        self.status_label.configure(text="Scan completed")
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def save_results(self):
        """Save scan results to a file in JSON or CSV format."""
        if not self.current_results:
            messagebox.showinfo("Info", "No results to save.")
            return
        format = self.format_var.get()
        filetypes = [("JSON files", "*.json")] if format == "json" else [("CSV files", "*.csv")]
        filename = filedialog.asksaveasfilename(defaultextension=f".{format}", filetypes=filetypes)
        if filename:
            self.scanner.live_hosts = self.current_results
            self.scanner.save_results(filename, format)
            messagebox.showinfo("Success", f"Results saved to {filename}")

if __name__ == "__main__":
    app = ScannerGUI()
    app.mainloop()