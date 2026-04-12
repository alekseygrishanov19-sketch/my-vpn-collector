import json, os, re, subprocess, time, requests, base64, random
from urllib.parse import urlparse, parse_qs, quote

# --- НАСТРОЙКИ ---
SNI_FILE, SOURCES_FILE, COUNTRY_FILE = "sni_list.txt", "sources.txt", "country_codes.json"
CHECK_URL, XRAY_PATH = "http://ip-api.com/json/?fields=countryCode", "./xray"
MAX_KEYS_TO_TEST = 150 # Сколько проверять за час
# -----------------

def load_list(f): return [l.strip().lower() for l in open(f, 'r') if l.strip() and not l.startswith('#')]
def load_json(f): return json.load(open(f, 'r')) if os.path.exists(f) else {}

def test_key_xray(link, white_list, countries):
    try:
        parsed = urlparse(link)
        if parsed.scheme != 'vless': return None
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        sni = params.get("sni", "").lower()
        pbk = params.get("pbk")
        
        # Конфиг Xray
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": parsed.hostname, "port": int(parsed.port), "users": [{"id": parsed.username, "encryption": "none"}]}]},
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": "reality" if pbk else "tls",
                    "realitySettings": {"serverName": sni, "publicKey": pbk, "shortId": params.get("sid", ""), "fingerprint": "chrome"} if pbk else {},
                    "tlsSettings": {"serverName": sni, "fingerprint": "chrome"} if not pbk else {}
                }
            }]
        }
        with open("temp.json", "w") as f: json.dump(config, f)
        
        proc = subprocess.Popen([XRAY_PATH, "-c", "temp.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        start_t = time.time()
        success, country_code, latency = False, "UN", 9999
        
        try:
            r = requests.get(CHECK_URL, proxies={"http":"socks5://127.0.0.1:10808","https":"socks5://127.0.0.1:10808"}, timeout=10)
            if r.status_code == 200:
                country_code = r.json().get("countryCode", "UN")
                latency = int((time.time() - start_t) * 1000)
                success = True
        except: pass
        
        proc.terminate()
        proc.wait()
        
        if success:
            country = countries.get(country_code, country_code)
            tag = f"{'REALITY' if pbk else 'TLS'}-{sni if sni else 'no-sni'}-{country}-{latency}ms".replace(' ', '_')
            return {"link": f"{link.split('#')[0]}#{quote(tag)}", "white": sni in white_list, "latency": latency, "id": f"{parsed.hostname}_{sni}"}
        return None
    except: return None

def main():
    white_list, countries = load_list(SNI_FILE), load_json(COUNTRY_FILE)
    sources = load_list(SOURCES_FILE)
    raw_links = []
    for url in sources:
        try: raw_links.extend(re.findall(r'vless://[^\s]+', requests.get(url, timeout=10).text))
        except: continue
    
    unique_links = list(set(raw_links))
    random.shuffle(unique_links)
    
    results_normal, results_white, seen_ids = [], [], set()
    for i, link in enumerate(unique_links[:MAX_KEYS_TO_TEST]):
        print(f"[{i+1}/{MAX_KEYS_TO_TEST}] Testing...", end='\r')
        res = test_key_xray(link, white_list, countries)
        if res and res["id"] not in seen_ids:
            if res["white"]: results_white.append(res)
            else: results_normal.append(res)
            seen_ids.add(res["id"])
            
    results_normal.sort(key=lambda x: x['latency'])
    results_white.sort(key=lambda x: x['latency'])
    
    w_list = [r['link'] for r in results_normal]
    wh_list = [r['link'] for r in results_white]
    
    with open("working.txt", "w") as f: f.write("\n".join(w_list))
    with open("whitelist.txt", "w") as f: f.write("\n".join(wh_list))
    with open("sub.txt", "w") as f: f.write(base64.b64encode("\n".join(w_list + wh_list).encode()).decode())
    print(f"\nDone! Saved: {len(w_list + wh_list)} keys.")

if __name__ == "__main__": main()
