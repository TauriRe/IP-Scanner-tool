#!/usr/bin/python3

import multiprocessing
import subprocess
import os
import ipaddress
import socket
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk, messagebox
import queue  # Import queue for progress updates

# Global set to avoid duplicates
processed_ips = set()

# Function to perform ARP scan and get MAC address
def get_mac_address(ip):
    try:
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
        packet = ether / arp_request
        result = srp(packet, timeout=2, verbose=False)[0]
        if result:
            return result[0][1].hwsrc
    except Exception:
        return "MAC not found"
    return "MAC not found"

# Pinger function (runs in worker processes)
def pinger(job_q, results_q, progress_q):
    DEVNULL = open(os.devnull, 'w')
    while True:
        ip = job_q.get()
        if ip is None:
            break

        # Avoid duplicates
        if ip in processed_ips:
            continue
        processed_ips.add(ip)

        # Ping
        try:
            subprocess.check_call(['ping', '-c2', ip], stdout=DEVNULL)
            # Resolve hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = ""
            # Get MAC
            mac_address = get_mac_address(ip)
            # Send results back to GUI
            results_q.put((ip, hostname, mac_address))
        except:
            # If ping fails or an exception happens, we ignore it
            pass

        # Instead of sending a fraction, send "1" to indicate this IP was processed
        progress_q.put(1)

# Generate a list of IP addresses from a subnet or range
def get_ip_range(subnet):
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
                    ip_list.append(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}")
            else:
                messagebox.showerror("Invalid Range", "Only the last octet can differ.")
        else:
            messagebox.showerror("Invalid Input", "Invalid subnet or range format.")
    return ip_list

def start_scan():
    """
    Kicks off the scan:
    1. Clears old data and progress.
    2. Spawns worker processes (pinger).
    3. Starts polling for results and progress updates.
    """
    global processed_ips
    processed_ips.clear()  # Reset before each scan

    # Clear the Treeview
    for item in tree.get_children():
        tree.delete(item)

    # Reset the progress bar
    progress_var.set(0)

    subnet = subnet_entry.get().strip()
    if not subnet:
        messagebox.showerror("Error", "Please enter a valid subnet.")
        return

    ip_list = get_ip_range(subnet)
    if not ip_list:
        messagebox.showerror("Error", "No valid IPs generated. Exiting.")
        return

    # We'll store everything needed by poll_results in a dict
    poll_data['total_ips'] = len(ip_list)
    poll_data['scanned_count'] = 0  # how many IPs have been processed so far

    # Create shared queues for jobs, results, and progress
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()
    progress_q = multiprocessing.Queue()

    poll_data['jobs'] = jobs
    poll_data['results_q'] = results
    poll_data['progress_q'] = progress_q

    pool_size = min(255, poll_data['total_ips'])

    # Create the worker processes
    pool = [
        multiprocessing.Process(target=pinger, args=(jobs, results, progress_q))
        for _ in range(pool_size)
    ]
    poll_data['pool'] = pool

    # Start each process
    for p in pool:
        p.start()

    # Add IPs to the jobs queue
    for ip in ip_list:
        if ip not in processed_ips:
            jobs.put(ip)

    # Add termination signals
    for _ in pool:
        jobs.put(None)

    # Start polling for results in the GUI
    poll_results()

def poll_results():
    """
    Periodically checks (polls) for new scan results and updates:
      - The Treeview with IP/hostname/MAC
      - The progress bar (based on # of processed IPs)
    Also checks if all worker processes are done.
    """
    # 1. Get any new results and insert them into the tree
    while not poll_data['results_q'].empty():
        try:
            ip, hostname, mac = poll_data['results_q'].get_nowait()
            tree.insert("", "end", values=(ip, hostname, mac))
        except queue.Empty:
            break

    # 2. Update the progress bar with however many IPs were scanned
    while True:
        try:
            _ = poll_data['progress_q'].get_nowait()
            poll_data['scanned_count'] += 1
        except queue.Empty:
            break

    # Set progress bar to percentage of scanned vs total
    if poll_data['total_ips'] > 0:
        fraction = poll_data['scanned_count'] / poll_data['total_ips']
        progress_var.set(fraction * 100)

    # 3. Check if worker processes are finished
    if any(p.is_alive() for p in poll_data['pool']):
        # Not done yet; check again after 200 ms
        root.after(200, poll_results)
    else:
        # Final drain of any remaining results in queue
        while not poll_data['results_q'].empty():
            try:
                ip, hostname, mac = poll_data['results_q'].get_nowait()
                tree.insert("", "end", values=(ip, hostname, mac))
            except queue.Empty:
                break

        progress_var.set(100)
        messagebox.showinfo("Scan Completed", "Scanning complete!")

# --------------------------- GUI SETUP ---------------------------
root = tk.Tk()
root.title("IP Scanner")
root.geometry("800x400")

# Dictionary for holding data needed by poll_results
poll_data = {
    'pool': None,          # list of processes
    'jobs': None,          # jobs queue
    'results_q': None,     # results queue
    'progress_q': None,    # progress queue
    'total_ips': 0,        # total IPs to scan
    'scanned_count': 0,    # how many IPs have been processed so far
}

# Input Section
frame_input = tk.Frame(root)
frame_input.pack(pady=10)

tk.Label(frame_input, text="Enter Subnet (e.g., 192.168.1.0/24 or 192.168.1.1-192.168.1.50):").grid(
    row=0, column=0, padx=5, pady=5
)
subnet_entry = tk.Entry(frame_input, width=30)
subnet_entry.grid(row=0, column=1, padx=5, pady=5)

start_button = tk.Button(frame_input, text="Start Scan", command=start_scan)
start_button.grid(row=0, column=2, padx=5, pady=5)

# Progress bar
progress_frame = tk.Frame(root)
progress_frame.pack(pady=10)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(progress_frame, variable=progress_var, maximum=100, length=500)
progress_bar.pack()

# Results Section
tree_frame = tk.Frame(root)
tree_frame.pack(pady=10, fill="both", expand=True)

columns = ("IP Address", "Hostname", "MAC Address")
tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
tree.heading("IP Address", text="IP Address")
tree.heading("Hostname", text="Hostname")
tree.heading("MAC Address", text="MAC Address")
tree.pack(fill="both", expand=True)

# Optional: Sorting buttons (uncomment if needed)

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
        key=lambda x: tree.item(x)['values'][1].lower(),
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


# ------------------------- LAUNCH GUI -------------------------
root.mainloop()
