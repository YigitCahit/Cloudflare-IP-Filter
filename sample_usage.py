from flask import Flask
from cloudflare_ip_filter import fetch_cloudflare_ips, restrict_to_cloudflare # cloudflare_ip_filter kütüphanesini dahil eder

app = Flask(__name__)
fetch_cloudflare_ips() # Cloudflare resmi sitesinden IP adreslerini çeker

@app.before_request # Her gelen istekten önce çalışacak fonksiyon
def check_ip():
    restrict_to_cloudflare(True) # İsteği gönderen IP adresinin, Cloudflare IP listesinde bulunup bulunmadığı kontrol eder

@app.route('/')
def index():
    return "This page is protected by Cloudflare."
