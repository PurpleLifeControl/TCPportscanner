import socket
import os
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading

# Function to check if the script is running with the necessary privileges (root on Linux/macOS)
def check_privileges():
    if os.name != 'nt':  # For Linux/macOS only
        if os.geteuid() != 0:
            print("[!] This script requires root privileges.")
            sys.exit(1)

# Function to grab service banner from HTTP or FTP
def grab_banner(target, port):
    try:
        # Attempt to open socket connection
        s = socket.socket()
        s.settimeout(1)
        s.connect((target, port))
        
        # Send a basic HTTP request for banner grabbing (only if HTTP or HTTPS)
        if port == 80 or port == 443:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode('utf-8')
            if banner:
                return banner.strip()
        
        # For FTP (port 21)
        if port == 21:
            s.send(b"USER anonymous\r\n")
            banner = s.recv(1024).decode('utf-8')
            if banner:
                return banner.strip()

        s.close()
    except Exception as e:
        return None

# Function to perform TCP connect scan (works without raw sockets)
def tcp_connect_scan(target, port, open_ports, closed_ports, filtered_ports, verbose=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        # Attempt connection to target port
        result = s.connect_ex((target, port))

        # Verbose output
        if verbose:
            print(f"[VERBOSE] Sent connection request to {target}:{port}")

        if result == 0:
            open_ports.append(port)
            print(f"[+] Port {port} is open")
            banner = grab_banner(target, port)
            if banner:
                print(f"    Service Banner: {banner}")
        else:
            closed_ports.append(port)
            print(f"[-] Port {port} is closed")

        s.close()

    except socket.error as e:
        filtered_ports.append(port)
        print(f"[?] Port {port} is filtered (Error: {e})")
    except Exception as e:
        filtered_ports.append(port)
        print(f"[?] Port {port} encountered an unexpected error: {e}")

# Function to scan multiple ports concurrently
def scan_ports(target, start_port, end_port, output_file, verbose=False):
    print(f"\nScanning target: {target}")
    print(f"Scanning ports {start_port} to {end_port}...\n")
    print("-" * 50)

    # Record start time
    start_time = datetime.now()

    open_ports = []
    closed_ports = []
    filtered_ports = []

    # Use ThreadPoolExecutor to scan multiple ports concurrently
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(tcp_connect_scan, target, port, open_ports, closed_ports, filtered_ports, verbose)

    # Record end time
    end_time = datetime.now()

    # Output summary statistics
    print("\nScan completed in:", end_time - start_time)
    print(f"Total Open Ports: {len(open_ports)}")
    print(f"Total Closed Ports: {len(closed_ports)}")
    print(f"Total Filtered Ports: {len(filtered_ports)}")
    print("-" * 50)

    # Save results to file (if output_file is provided)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(f"Scan completed on {datetime.now()}\n")
            f.write(f"Target: {target}\n")
            f.write(f"Ports scanned: {start_port} to {end_port}\n\n")
            f.write("Open Ports:\n")
            for port in open_ports:
                f.write(f"{port}\n")
            f.write("\nClosed Ports:\n")
            for port in closed_ports:
                f.write(f"{port}\n")
            f.write("\nFiltered Ports:\n")
            for port in filtered_ports:
                f.write(f"{port}\n")
            f.write("\nScan completed in: " + str(end_time - start_time) + "\n")

            print(f"\nResults saved to {output_file}")

    print("-" * 50)

# Function to validate target
def validate_target(target):
    try:
        # Check if the target is a valid IP address or hostname
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        print(f"[-] Invalid target address: {target}")
        return False

def get_input(prompt, default=None, type_func=str):
    """Helper function to handle user input and ensure proper validation"""
    user_input = input(prompt + (f" (default: {default}): " if default else ": "))
    if not user_input and default is not None:
        return default
    try:
        return type_func(user_input)
    except ValueError:
        print(f"[!] Invalid input. Expected {type_func.__name__}.")
        return get_input(prompt, default, type_func)

if __name__ == "__main__":
    # Check for root/admin privileges (Linux/macOS only)
    check_privileges()

    # Interactive Input
    print("Welcome to the Port Scanner!")
    target = get_input("Enter target IP address or domain")
    if not validate_target(target):
        exit(1)

    start_port = get_input("Enter starting port", default=1, type_func=int)
    end_port = get_input("Enter ending port", default=10000, type_func=int)  # Default set to 10000
    save_results = get_input("Do you want to save results to a file? (y/n)", default="n").lower() == "y"
    verbose = get_input("Do you want verbose output? (y/n)", default="n").lower() == "y"

    output_file = None
    if save_results:
        output_file = get_input("Enter the output filename", default="scan_results.txt")

    # Start scanning
    scan_ports(target, start_port, end_port, output_file, verbose)
