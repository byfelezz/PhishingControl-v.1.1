import tkinter as tk
from tkinter import messagebox
import re
import requests
from socket import gethostbyname
from urllib.parse import urlparse

# WHOIS API anahtarınızı burada tanımlayın
WHOIS_API_KEY = "YOUR_WHOIS_API_KEY"

def is_phishing_url(url):
    phishing_patterns = [
        r"(http|https)://[A-Za-z0.9.-]*\.tk/",
        r"(http|https)://[A-Za-z0.9.-]*\.ml/",
    ]

    for pattern in phishing_patterns:
        if re.search(pattern, url):
            return "Bu bir phishing URL'si olabilir."

    return "Bu güvenli bir URL gibi görünüyor."

def check_ssl_certificate(url):
    try:
        response = requests.get(url, verify=True)
        if response.status_code == 200:
            return "SSL Sertifikası Durumu: Geçerli"
        else:
            return "SSL Sertifikası Durumu: Geçerli Değil"
    except requests.exceptions.SSLError:
        return "SSL Sertifikası Durumu: Geçerli Değil (Potansiyel Güvenlik Riski)"
    except requests.exceptions.RequestException:
        return "SSL Sertifikası Durumu: Bağlantı Hatası"

def check_url_redirects(url):
    try:
        response = requests.head(url, allow_redirects=True)
        if len(response.history) > 0:
            redirect_chain = [response.url] + [r.url for r in response.history]
            return f"URL Yönlendirmeleri: {len(response.history)} kez yönlendiriliyor: {', '.join(redirect_chain)}"
        else:
            return "URL Yönlendirmeleri: Yönlendirme Yok"
    except requests.exceptions.RequestException:
        return "URL Yönlendirmeleri: Bağlantı Hatası"

def resolve_ip_address(url):
    try:
        domain = urlparse(url).hostname
        ip_address = gethostbyname(domain)
        return f"URL'nin bağlandığı IP adresi: {ip_address}"
    except Exception as e:
        return "URL'nin bağlandığı IP adresi: Çözümlenemedi"

def get_whois_info(url):
    try:
        domain = urlparse(url).hostname
        whois_api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}"
        response = requests.get(whois_api_url)
        
        if response.status_code == 200:
            return "WHOIS Bilgileri:\n" + response.text
        else:
            return "WHOIS bilgilerine erişilemedi."
    except Exception as e:
        return "WHOIS bilgilerine erişilemedi."

def analyze_url():
    url = entry.get()
    if not url:
        messagebox.showerror("Hata", "URL girmelisiniz.")
        return

    phishing_result = is_phishing_url(url)
    ssl_result = check_ssl_certificate(url)
    redirect_result = check_url_redirects(url)
    ip_result = resolve_ip_address(url)
    whois_info = get_whois_info(url)

    result_text = f"URL: {url}\n"
    result_text += f"Phishing Kontrolü: {phishing_result}\n"
    result_text += f"SSL Sertifikası Durumu: {ssl_result}\n"
    result_text += f"URL Yönlendirmeleri: {redirect_result}\n"
    result_text += f"{ip_result}\n"

    if whois_info and whois_info != "WHOIS bilgilerine erişilemedi.":
        result_text += whois_info
    else:
        result_text += "WHOIS bilgilerine erişilemedi."

    result.config(state=tk.NORMAL)
    result.delete(1.0, tk.END)
    result.insert(tk.END, result_text)
    result.config(state=tk.DISABLED)

window = tk.Tk()
window.title("URL Analiz Aracı")

entry_label = tk.Label(window, text="URL Girin:")
entry_label.pack()
entry = tk.Entry(window, width=50)
entry.pack()

analyze_button = tk.Button(window, text="URL'yi Analiz Et", command=analyze_url)
analyze_button.pack()

result = tk.Text(window, height=15, width=70)
result.config(state=tk.DISABLED)
result.pack()
result.tag_config("green", foreground="green")

window.mainloop()
