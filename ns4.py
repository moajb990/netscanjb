import scapy.all as scapy
import nmap
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

# Function to get hostname of an IP
def get_hostname(ip):
    try:
        return scapy.gethostbyaddr(ip)[0]
    except:
        return None

# Scan func
def scan(network_ip):
    arp_request = scapy.ARP(pdst=network_ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    client_list = []
    for ans in answered:
        client_dict = {
            "ip": ans[1].psrc,
            "mac": ans[1].hwsrc,
            "hostname": get_hostname(ans[1].psrc)
        }
        client_list.append(client_dict)
    
    return client_list

# Scan for open ports with nmap ._.
def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='--open')
    return nm[ip]['tcp'].keys() if ip in nm.all_hosts() else []

# Function to run the scan and show the results in a beautiful way
def run_scan():
    network_ip = ip_entry.get()
    if not network_ip:
        messagebox.showerror("Error", "Please enter a network IP range.")
        return
    
    # Clear the previous results in the Treeview
    for row in tree.get_children():
        tree.delete(row)
    
    # Scanning the network
    clients = scan(network_ip)
    if not clients:
        messagebox.showinfo("Result", "No devices found on the network.")
        return
    
    # Display the results in the Treeview
    for client in clients:
        ports = scan_ports(client['ip'])
        ports_str = ', '.join(map(str, ports)) if ports else "No open ports"
        tree.insert("", tk.END, values=(client['ip'], client['mac'], client['hostname'] or "Unknown", ports_str))

# Create the main window
root = tk.Tk()
root.title("Network Scanner")
root.geometry("800x500")
root.configure(bg="#f0f0f0")

# Style configuration 
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=6, background="#4CAF50", foreground="white")
style.map("TButton", background=[("active", "#45a049")])
style.configure("TLabel", font=("Arial", 12), background="#f0f0f0")
style.configure("Treeview", font=("Arial", 10), rowheight=25)
style.configure("Treeview.Heading", font=("Arial", 11, "bold"))

# Input field for IP range
ip_label = ttk.Label(root, text="Enter Network IP Range:")
ip_label.pack(pady=10)

ip_entry = ttk.Entry(root, width=40, font=("Arial", 12))
ip_entry.pack(pady=5)

# Button to start scan
scan_button = ttk.Button(root, text="Scan Network", command=run_scan)
scan_button.pack(pady=10)

# Creating a Treeview to display the output in a tabular format
columns = ("IP Address", "MAC Address", "Hostname", "Open Ports")
tree = ttk.Treeview(root, columns=columns, show="headings", selectmode="none")
tree.heading("IP Address", text="IP Address")
tree.heading("MAC Address", text="MAC Address")
tree.heading("Hostname", text="Hostname")
tree.heading("Open Ports", text="Open Ports")
tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Adding scrollbar to the Treeview
tree_scroll = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
tree.configure(yscroll=tree_scroll.set)
tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

# Start the Tkinter loop
root.mainloop()
#gg?
