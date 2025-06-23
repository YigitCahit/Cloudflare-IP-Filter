import requests
import ipaddress
from flask import request, abort
from colorama import Fore, init

init(autoreset=True)  

CLOUDFLARE_IP_LIST_URL = "https://api.cloudflare.com/client/v4/ips" # Clodflare'ın IPv4 listesini içeren bağlantı
cloudflare_networks = [] # IP adreslerini depolayacak liste

def fetch_cloudflare_ips(): # IP adreslerini çeken fonksiyon
    global cloudflare_networks # IP adreslerini depolayacak liste global hale getiriliyor
    try:
        response = requests.get(CLOUDFLARE_IP_LIST_URL) # GET isteği ile IP listesi alınıyor
        data = response.json() # Cloudflare'ın döndürdüğü veriler data değişkenine atanıyor
        if data.get("success"): # İşlemin başarılı olup olmadığı kontrol ediliyor
            ipv4_cidrs = data["result"]["ipv4_cidrs"] # Data içerisinden IPv4 alınıyor
            cloudflare_networks = [ipaddress.ip_network(cidr) for cidr in ipv4_cidrs] # Bir döngü ile IP adresleri cloudflare_networks listesine atanıyor
            print(Fore.GREEN + "Cloudflare IP ranges loaded successfully.")
        else:
            print(Fore.RED + "Failed to retrieve Cloudflare IP list.")
    except Exception as e:
        print(Fore.RED + f"Error while fetching Cloudflare IPs: {e}")

def is_cloudflare_ip(): # IP adresinin Clodflare'dan gelip gelmediğini kontrol eden fonksiyon
    try:
        remote_ip = ipaddress.ip_address(request.remote_addr) # İstek gönderen IP adresini alır
        return any(remote_ip in net for net in cloudflare_networks) # IP adresinin cloudflare_networks listesinde olup olmadığı kontrol ediliyor
    except Exception as e:
        print(Fore.RED + f"IP check error: {e}")
        return False

def restrict_to_cloudflare(Log): # IP, cloudflare_networks içinde yoksa erişimi engelleyecek fonksiyon
    if is_cloudflare_ip():
        real_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(',')[0].strip() # İstek başlıklarından gerçek IP bulunur
        if Log==True:
            print(Fore.GREEN + f"Allowed access. Real IP: {real_ip}") # Gerçek IP yazdırılır
    else:
        if Log==True:
            print(Fore.RED + f"Blocked IP access: {request.remote_addr}")
        abort(403) # is_cloudflare_ip() False döndürürse IP daresi Cloudflare'a ait değildir. Bu sebeple Bağlantı abort edilir
