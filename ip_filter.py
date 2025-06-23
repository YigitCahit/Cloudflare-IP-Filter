import requests
import ipaddress
from flask import request, abort
from colorama import Fore, init

init(autoreset=True)  

CLOUDFLARE_IP_LIST_URL = "https://api.cloudflare.com/client/v4/ips"
cloudflare_networks = []

def fetch_cloudflare_ips():
    global cloudflare_networks
    try:
        response = requests.get(CLOUDFLARE_IP_LIST_URL)
        data = response.json()
        if data.get("success"):
            ipv4_cidrs = data["result"]["ipv4_cidrs"]
            cloudflare_networks = [ipaddress.ip_network(cidr) for cidr in ipv4_cidrs]
            print(Fore.GREEN + "Cloudflare IP ranges loaded successfully.")
        else:
            print(Fore.RED + "Failed to retrieve Cloudflare IP list.")
    except Exception as e:
        print(Fore.RED + f"Error while fetching Cloudflare IPs: {e}")

def is_cloudflare_ip():
    try:
        remote_ip = ipaddress.ip_address(request.remote_addr)
        return any(remote_ip in net for net in cloudflare_networks)
    except Exception as e:
        print(Fore.RED + f"IP check error: {e}")
        return False

def restrict_to_cloudflare(Log):
    if is_cloudflare_ip():
        real_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(',')[0].strip()
        if Log==True:
            print(Fore.GREEN + f"Allowed access. Real IP: {real_ip}")
    else:
        if Log==True:
            print(Fore.RED + f"Blocked IP access: {request.remote_addr}")
        abort(403)
