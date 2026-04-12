
import json, os, re, subprocess, time, requests, base64, random, socket
from urllib.parse import urlparse, parse_qs, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- НАСТРОЙКИ ---
SNI_FILE, SOURCES_FILE, COUNTRY_FILE = "sni_list.txt", "sources.txt", "country_codes.json"
CHECK_URL, XRAY_PATH = "http://ip-api.com/json/?fields=countryCode", "./xray"
PORT_THREADS = 150  
XRAY_THREADS = 40   
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
# -----------------

def load_list(f): 
    if not os.path.exists(f): return []
    return [l.strip().lower() for l in open(f, 'r', encoding='utf-8') if l.strip() and not l.startswith('#')]

def load_json(f): 
    if not os.path.exists(f): return {}
    with open(f, 'r', encoding='utf-8') as file:
        try: return json.load(file)
        except: return {}

def is_port_open(link):
    try:
        parsed = urlparse(link.strip())
        if not parsed.hostname or not parsed.port: return None
        with socket.create_connection((parsed.hostname, int(parsed.port)), timeout=5):
            return link.strip()
    except: return None

def test_xray_worker(link, white_list, countries, thread_id):
    try:
        parsed = urlparse(link)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        
        transport = params.get("type", "tcp")
        security = params.get("security", "none")
        sni = params.get("sni") or params.get("host", "")
        pbk = params.get("pbk")
        socks_port = 11000 + thread_id
        
        # Конфиг под xhttp и прочее
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": socks_port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{"address": parsed.hostname, "port": int(parsed.port), "users": [{"id": parsed.username, "encryption": "none"}]}]
                },
                "streamSettings": {
                    "network": transport,
                    "security": security if security != "none" else "",
                    "tlsSettings": {"serverName": sni, "fingerprint": "chrome"} if security == "tls" else {},
                    "realitySettings": {"serverName": sni, "publicKey": pbk, "shortId": params.get("sid", ""), "fingerprint": "chrome"} if security == "reality" else {},
                    "xhttpSettings": {
                        "path": unquote(params.get("path", "/")),
                        "host": params.get("host", ""),
                        "mode": params.get("mode", "auto")
                    } if transport == "xhttp" else {}
                }
            }]
        }
        
        cfg_name = f"tmp_{thread_id}.json"
        with open(cfg_name, "w") as f: json.dump(config, f)
        
        proc = subprocess.Popen([XRAY_PATH, "-c", cfg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        success, country_code, latency = False, "UN", 9999
        try:
            proxies = {"http":f"socks5://127.0.0.1:{socks_port}","https":f"socks5://127.0.0.1:{socks_port}"}
            st = time.time()
            r = requests.get(CHECK_URL, proxies=proxies, timeout=10)
            if r.status_code == 200:
                country_code = r.json().get("countryCode", "UN")
                latency = int((time.time() - st) * 1000)
                success = True
        except: pass
        
        proc.terminate()
        try: os.remove(cfg_name)
        except: pass
        
        if success:
            country = countries.get(country_code, country_code)
            tag = f"{country}-{transport}-{sni if sni else 'node'}-{latency}ms".replace(' ', '_')
            return {"link": f"{link.split('#')[0]}#{quote(tag)}", "white": sni in white_list, "latency": latency, "id": f"{parsed.hostname}_{sni}_{transport}"}
    except: pass
    return None

def main():
    white_list, countries = load_list(SNI_FILE), load_json(COUNTRY_FILE)
    sources = load_list(SOURCES_FILE)
    
    print(f"--- 1. Сбор ссылок ---")
    raw_links = []
    for url in sources:
        try:
            # Исправляем ссылку, если это обычная ссылка на гитхаб, а не RAW
            fixed_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            resp = requests.get(fixed_url, headers=HEADERS, timeout=15)
            content = resp.text
            
            print(f"URL: {fixed_url} | Статус: {resp.status_code}")
            print(f"Начало текста: {content[:100].strip()}...") # ДИАГНОСТИКА

            # Агрессивный метод сбора: режем по строке 'vless://'
            found = []
            if 'vless://' in content:
                parts = content.split('vless://')
                for p in parts[1:]: # пропускаем всё, что было до первого vless
                    # берем текст до конца строки
                    link = 'vless://' + p.split('\n')[0].split('\r')[0].strip()
                    found.append(link)
            
            # Если не нашли, пробуем Base64 (вдруг там вся подписка закодирована)
            if not found:
                try:
                    decoded = base64.b64decode(content.strip()).decode('utf-8')
                    parts = decoded.split('vless://')
                    for p in parts[1:]:
                        link = 'vless://' + p.split('\n')[0].split('\r')[0].strip()
                        found.append(link)
                except: pass
                
            raw_links.extend(found)
            print(f"Найдено {len(found)} ссылок.")
        except Exception as e:
            print(f"Ошибка источника {url}: {e}")
    
    unique_links = list(set([l for l in raw_links if len(l) > 20]))
    if not unique_links:
        print("!!! Ключи не найдены. Скрипт завершен.")
        return

    print(f"--- 2. Чек портов ({len(unique_links)} шт.) ---")
    alive_ports = []
    with ThreadPoolExecutor(max_workers=PORT_THREADS) as executor:
        futures = [executor.submit(is_port_open, link) for link in unique_links]
        for f in as_completed(futures):
            res = f.result()
            if res: alive_ports.append(res)
    
    print(f"Порты открыты: {len(alive_ports)}")

    print(f"--- 3. Тест Xray ---")
    results = []
    seen_ids = set()
    with ThreadPoolExecutor(max_workers=XRAY_THREADS) as executor:
        futures = [executor.submit(test_xray_worker, link, white_list, countries, i % XRAY_THREADS) for i, link in enumerate(alive_ports)]
        for f in as_completed(futures):
            res = f.result()
            if res and res["id"] not in seen_ids:
                results.append(res)
                seen_ids.add(res["id"])

    # Сохранение
    results.sort(key=lambda x: x['latency'])
    final_links = [r['link'] for r in results]
    
    with open("working.txt", "w", encoding='utf-8') as f: f.write("\n".join(final_links))
    
    if final_links:
        sub_64 = base64.b64encode("\n".join(final_links).encode()).decode()
        with open("sub.txt", "w", encoding='utf-8') as f: f.write(sub_64)
        print(f"Готово! Рабочих: {len(final_links)}")
    else:
        print("Живых ключей не найдено.")

if __name__ == "__main__": main()
