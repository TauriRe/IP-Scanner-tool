#!/usr/bin/python3

import multiprocessing
import subprocess
import os
import ipaddress
import socket
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import queue  # For progress updates

import requests  # For HTTP banner
from nmb.NetBIOS import NetBIOS  # For NetBIOS lookups
# If "NetBIOSTimeout" isn't in your version, just catch Exception.

processed_ips = set()

# Ports we want to check
PORTS_TO_SCAN = [22, 23, 80, 443, 8080, 8443]

def check_port_open(ip, port, timeout=1.5):
    """
    Attempt a TCP connect to <ip>:<port> with a short timeout.
    Returns True if open, False otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False

def get_http_banner(ip, port=80, timeout=2):
    """
    Attempt an HTTP GET on http://<ip>:<port>/ and return 'Server' header or <title>.
    """
    url = f"http://{ip}:{port}/"
    try:
        r = requests.get(url, timeout=timeout)
        # Try 'Server' header
        server = r.headers.get('Server', '')
        if server:
            return server  # e.g., "Apache/2.4.41 (Ubuntu)"

        # Or parse <title> from HTML
        if r.text:
            start_idx = r.text.lower().find("<title>")
            end_idx   = r.text.lower().find("</title>")
            if start_idx != -1 and end_idx != -1:
                return r.text[start_idx+7:end_idx].strip()
    except:
        pass
    return None

def netbios_name_lookup(ip, timeout=2):
    """
    Attempt a unicast NetBIOS name lookup for the given IP (UDP 137).
    Returns something like "DESKTOP-ABC123" if it responds.
    """
    nb = NetBIOS()
    try:
        result = nb.queryIPForName(ip, timeout=timeout)
        if result:
            return result[0]
        return None
    except:
        return None
    finally:
        nb.close()

def get_mac_address(ip):
    """
    On Windows local subnet, parse 'arp -a' for a MAC.
    For remote subnets, you'll likely see the gateway's MAC or 'MAC not found'.
    """
    try:
        output = subprocess.check_output(["arp", "-a"], shell=True).decode(errors='ignore')
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == ip:
                return parts[1]
    except:
        pass
    return "MAC not found"

def pinger(job_q, results_q, progress_q):
    """
    Worker process:
      1. Ping each IP.
      2. If pinged, try DNS, NetBIOS, HTTP banner, port scan, get MAC
      3. Push (ip, hostname, mac, open_ports) to results_q
    """
    creationflags = 0
    if sys.platform.startswith("win"):
        creationflags = subprocess.CREATE_NO_WINDOW

    DEVNULL = open(os.devnull, 'w')

    while True:
        ip = job_q.get()
        if ip is None:
            break

        if ip in processed_ips:
            continue
        processed_ips.add(ip)

        # Ping
        ret = subprocess.call(
            ['ping', '-n', '2', ip],
            stdout=DEVNULL,
            stderr=DEVNULL,
            creationflags=creationflags
        )

        hostname = ""
        open_ports = []

        if ret == 0:
            # 1. DNS Reverse
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                pass

            # 2. NetBIOS if DNS failed
            if not hostname:
                nb_name = netbios_name_lookup(ip)
                if nb_name:
                    hostname = nb_name

            # 3. HTTP banner check if still no hostname (port 80, 443)
            if not hostname:
                for test_port in [80, 443]:
                    banner = get_http_banner(ip, port=test_port)
                    if banner:
                        hostname = banner
                        break

            # 4. Quick port scan on the specified ports
            for port in PORTS_TO_SCAN:
                if check_port_open(ip, port):
                    open_ports.append(port)

            # 5. MAC address (local subnets only)
            mac_address = get_mac_address(ip)

            # Convert list of open ports to string for display
            if open_ports:
                open_ports_str = ",".join(str(p) for p in open_ports)
            else:
                open_ports_str = ""

            results_q.put((ip, hostname, mac_address, open_ports_str))

        progress_q.put(1)

def get_ip_range(subnet):
    """
    Return a list of IPs from a CIDR or dash notation.
    """
    import ipaddress
    ip_list = []
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        ip_list = [str(ip) for ip in net.hosts()]
    except ValueError:
        if '-' in subnet:
            start_ip, end_ip = subnet.split('-')
            start_parts = start_ip.split('.')
            end_parts = end_ip.split('.')
            if start_parts[:3] == end_parts[:3]:
                for i in range(int(start_parts[3]), int(end_parts[3]) + 1):
                    ip_list.append(
                        f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}"
                    )
            else:
                messagebox.showerror("Invalid Range", "Only the last octet can differ.")
        else:
            messagebox.showerror("Invalid Input", "Invalid subnet or range format.")
    return ip_list

def start_scan():
    global processed_ips
    processed_ips.clear()

    for item in tree.get_children():
        tree.delete(item)

    progress_var.set(0)

    subnet = subnet_entry.get().strip()
    if not subnet:
        messagebox.showerror("Error", "Please enter a valid subnet or range.")
        return

    ip_list = get_ip_range(subnet)
    if not ip_list:
        messagebox.showerror("Error", "No valid IPs generated.")
        return

    poll_data['total_ips'] = len(ip_list)
    poll_data['scanned_count'] = 0

    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()
    progress_q = multiprocessing.Queue()

    poll_data['jobs'] = jobs
    poll_data['results_q'] = results
    poll_data['progress_q'] = progress_q

    pool_size = min(32, poll_data['total_ips'])

    pool = [
        multiprocessing.Process(target=pinger, args=(jobs, results, progress_q))
        for _ in range(pool_size)
    ]
    poll_data['pool'] = pool

    for p in pool:
        p.start()

    for ip in ip_list:
        if ip not in processed_ips:
            jobs.put(ip)

    for _ in range(pool_size):
        jobs.put(None)

    poll_results()

def poll_results():
    # Drain results
    while not poll_data['results_q'].empty():
        try:
            ip, hostname, mac, open_ports = poll_data['results_q'].get_nowait()
            # Insert into Treeview
            tree.insert("", "end", values=(ip, hostname, mac, open_ports))
        except queue.Empty:
            break

    # Update progress
    while True:
        try:
            _ = poll_data['progress_q'].get_nowait()
            poll_data['scanned_count'] += 1
        except queue.Empty:
            break

    if poll_data['total_ips'] > 0:
        fraction = poll_data['scanned_count'] / poll_data['total_ips']
        progress_var.set(fraction * 100)

    if any(p.is_alive() for p in poll_data['pool']):
        root.after(200, poll_results)
    else:
        while not poll_data['results_q'].empty():
            try:
                ip, hostname, mac, open_ports = poll_data['results_q'].get_nowait()
                tree.insert("", "end", values=(ip, hostname, mac, open_ports))
            except queue.Empty:
                break

        progress_var.set(100)
        messagebox.showinfo("Scan Completed", "Scanning complete!")

def on_tree_double_click(event):
    row_id = tree.identify_row(event.y)
    col_id = tree.identify_column(event.x)
    if not row_id:
        return
    row_values = tree.item(row_id, 'values')
    # row_values = (IP, Hostname, MAC, Ports)
    if col_id == '#1':
        copy_text = row_values[0]
        col_name = "IP Address"
    elif col_id == '#2':
        copy_text = row_values[1]
        col_name = "Hostname"
    elif col_id == '#3':
        copy_text = row_values[2]
        col_name = "MAC Address"
    elif col_id == '#4':
        copy_text = row_values[3]
        col_name = "Open Ports"
    else:
        return

    root.clipboard_clear()
    root.clipboard_append(copy_text)
    root.update()
    messagebox.showinfo("Copied", f"Copied {col_name}:\n\n{copy_text}")

def main_gui():
    global root, poll_data, subnet_entry, progress_var, tree

    root = tk.Tk()
    root.title("IP Scanner with Port Scan")
    root.geometry("900x400")

    poll_data = {
        'pool': None,
        'jobs': None,
        'results_q': None,
        'progress_q': None,
        'total_ips': 0,
        'scanned_count': 0,
    }

    frame_input = tk.Frame(root)
    frame_input.pack(pady=10)

    tk.Label(frame_input, text="Enter Subnet/Range:").grid(row=0, column=0, padx=5, pady=5)
    subnet_entry = tk.Entry(frame_input, width=30)
    subnet_entry.grid(row=0, column=1, padx=5, pady=5)

    start_btn = tk.Button(frame_input, text="Start Scan", command=start_scan)
    start_btn.grid(row=0, column=2, padx=5, pady=5)

    progress_frame = tk.Frame(root)
    progress_frame.pack(pady=10)

    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(progress_frame, variable=progress_var, maximum=100, length=500)
    progress_bar.pack()

    tree_frame = tk.Frame(root)
    tree_frame.pack(pady=10, fill="both", expand=True)

    # columns: IP, Hostname, MAC, Ports
    columns = ("IP Address", "Hostname", "MAC Address", "Open Ports")
    tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
    tree.heading("IP Address", text="IP Address")
    tree.heading("Hostname", text="Hostname")
    tree.heading("MAC Address", text="MAC Address")
    tree.heading("Open Ports", text="Open Ports")
    tree.pack(fill="both", expand=True)

    tree.bind("<Double-Button-1>", on_tree_double_click)

    def sort_by_ip(ascending=True):
        rows = list(tree.get_children())
        rows.sort(
            key=lambda x: [int(num) for num in tree.item(x)['values'][0].split('.')],
            reverse=not ascending
        )
        for row in rows:
            tree.move(row, '', 'end')

    def sort_by_hostname(ascending=True):
        rows = list(tree.get_children())
        rows.sort(
            key=lambda x: (tree.item(x)['values'][1] or "").lower(),
            reverse=not ascending
        )
        for row in rows:
            tree.move(row, '', 'end')

    button_sort_frame = tk.Frame(root)
    button_sort_frame.pack(pady=5)
    tk.Button(button_sort_frame, text="Sort IP (Asc)",
              command=lambda: sort_by_ip(True)).pack(side="left", padx=5)
    tk.Button(button_sort_frame, text="Sort IP (Desc)",
              command=lambda: sort_by_ip(False)).pack(side="left", padx=5)
    tk.Button(button_sort_frame, text="Sort Host (Asc)",
              command=lambda: sort_by_hostname(True)).pack(side="left", padx=5)
    tk.Button(button_sort_frame, text="Sort Host (Desc)",
              command=lambda: sort_by_hostname(False)).pack(side="left", padx=5)

    root.mainloop()

if __name__ == '__main__':
    multiprocessing.freeze_support()
    main_gui()
