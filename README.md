# TCPportscanner

TCP Port Scanner with Banner Grabbing

This is a simple Python script to scan TCP ports on any target (IP or domain) to see which ones are open, closed, or filtered. It also grabs service banners from HTTP (port 80, 443) and FTP (port 21), so you can get some basic info about what’s running on those ports (like which web server or FTP software).

The script uses concurrent scanning, which means it scans multiple ports at once to save you time, especially if you’re scanning a large range of ports. Plus, it checks if you have root/admin permissions (on Linux/macOS) because some ports might need special access to scan.
Features:

    Port Scanning: Finds out if a port is open, closed, or blocked by a firewall.
    Banner Grabbing: Gathers basic info from HTTP and FTP services (like server versions).
    Fast Scanning: Scans multiple ports at the same time to speed things up.
    Permissions Check: Makes sure you’ve got the right permissions to scan on Linux/macOS.
    Customizable: Choose your own port range, decide if you want to save the results, and toggle verbose output for more details.
    Easy to Use: Just follow the prompts to input the target and scan settings.

How to Use:

    Download or clone the repo.
    Run the script with Python 3.x.
    Enter the target address (IP or domain), select your port range, and choose if you want to save the results or see extra details.

Example:

python3 port_scanner.py
