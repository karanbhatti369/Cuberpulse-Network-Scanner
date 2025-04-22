# CyberPulse Network Scanner

A Python-based GUI tool designed for IT support professionals to troubleshoot network connectivity issues. Built with `customtkinter`, it features a modern, dark-themed interface with real-time logs, dual progress bars, and a scrollable results table, making it ideal for diagnosing network devices and services.

## Features

- **Network Scanning**: Scans subnets (e.g., `192.168.0.0/24`) to detect live hosts and guess OS via TTL.
- **Port Checking**: Scans common ports (21, 22, 80, 443) or custom ranges with concurrent threading.
- **Real-Time Feedback**: Side-by-side logs and progress bars for host discovery and port scanning.
- **Results Table**: Displays IP, OS, and open ports in a scrollable table.
- **Scan History**: Saves up to 5 past scans in a sidebar for quick review.
- **Export Options**: Saves results as JSON or CSV for reporting.
- **User-Friendly Design**: Includes tooltips, inline error messages, and a cancel scan feature.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/your-username/network-scanner.git
   cd network-scanner
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Requirements**:

   - Python 3.8+
   - `customtkinter` (included in `requirements.txt`)
   - Windows/Linux (for ping compatibility)

## Usage

1. Run the application:

   ```bash
   python network_scanner.py
   ```

2. Enter a subnet (e.g., `192.168.1`), select ports (checkboxes or custom, e.g., `8080,1000-2000`), and set a timeout (e.g., `1.0`).

3. Click **Initiate Scan** to start.

4. Monitor logs and progress bars in real-time.

5. View results in the table, save as JSON/CSV, or load past scans from the history sidebar.

## Screenshots

- **Main Interface**: Input fields and history sidebar.
- **Scan in Progress**: Real-time logs and progress bars.
- **Results Table**: Detailed scan results.

## Testing

- **Setup**: Install dependencies and run `python network_scanner.py`.
- **Scan**: Test with subnet `192.168.1`, ports 80/443, and timeout 1.0.
- **Features**: Verify logs, progress bars, results table, history, and export.
- **Edge Cases**: Test invalid inputs (e.g., subnet `256.168.0`) and window resizing.

## Notes

- Ensure your firewall allows ICMP (ping) and TCP connections for scanning.
- Designed for Level 1 IT support roles, showcasing skills in Python, GUI design, networking, and user-centric error handling.
- Future enhancements may include persistent history, button icons, and results sorting.

