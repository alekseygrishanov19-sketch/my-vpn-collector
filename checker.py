import json, os, re, subprocess, time, requests
from urllib.parse import urlparse, parse_qs, quote

SNI_FILE, SOURCES_FILE, COUNTRY_FILE = "sni_list.txt", "sources.txt", "country_codes.json"
CHECK_URL, SINGBOX_PATH = "https://www.google.com/generate_204", "./sing-box"

def load_list(f): return [l.strip().lower() for l in open(f, 'r') if l.strip() and not l.startswith('#')]
def load_json(f): return json.load(open(f, 'r')) if os.path.exists(f) else {}

def get_country(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5).json()
        return load_json(COUNTRY_FILE).get(resp.get("countryCode"), resp.get("countryCode", "Unknown"))
    except: return "Unknown"

def test_key(link, white_list):
    try:
        parsed = urlparse(link)
        if parsed.scheme != 'vless': return None
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        sni = params.get("sni", "").lower()
        
        sb_config = {
            "outbounds": [{
                "type": "vless", "tag": "proxy", "server": parsed.hostname, "server_port": int(parsed.port),
                "uuid": parsed.username, "packet_encoding": "xudp",
                "tls": {"enabled": True, "server_name": sni, "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": params.get("pbk"), "short_id": params.get("sid")} if params.get("pbk") else None}
            }],
            "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 10808}]
        }
        with open("temp.json", "w") as f: json.dump(sb_config, f)
        
        proc = subprocess.Popen([SINGBOX_PATH, "run", "-c", "temp.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        success = False
        try:
            r = requests.get(CHECK_URL, proxies={"http":"socks5://127.0.0.1:10808","https":"socks5://127.0.0.1:10808"}, timeout=7)
            if r.status_code in [200, 204]: success = True
        except: pass
        
        proc.terminate()
        if success:
            country = get_country(parsed.hostname)
            new_name = f"vless-{sni if sni else 'no-sni'}-{country.replace(' ', '_')}"
            return {"link": f"{link.split('#')[0]}#{quote(new_name)}", "white": sni in white_list}
        return None
    except: return None

def main():
    white_list, sources = load_list(SNI_FILE), load_list(SOURCES_FILE)
    raw_links = []
    for url in sources:
        try: raw_links.extend(re.findall(r'vless://[^\s]+', requests.get(url, timeout=10).text))
        except: continue
    
    unique_links = list(set(raw_links))
    working_normal, working_white = [], []
    
    for i, link in enumerate(unique_links[:150]): # Проверяем 150 свежих ключей
        res = test_key(link, white_list)
        if res:
            if res["white"]: working_white.append(res["link"])
            else: working_normal.append(res["link"])
            
    with open("working.txt", "w") as f: f.write("\n".join(working_normal))
    with open("whitelist.txt", "w") as f: f.write("\n".join(working_white))

if __name__ == "__main__": main()
