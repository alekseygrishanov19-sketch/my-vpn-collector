import json, os, re, subprocess, time, requests, base64, random, socket
from urllib.parse import urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- НАСТРОЙКИ ---
SNI_FILE, SOURCES_FILE, COUNTRY_FILE = "sni_list.txt", "sources.txt", "country_codes.json"
CHECK_URL, XRAY_PATH = "http://ip-api.com/json/?fields=countryCode", "./xray"
PORT_THREADS = 150  
XRAY_THREADS = 40   
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
        parsed = urlparse(link)
        if not parsed.hostname or not parsed.port: return None
        # Проверка порта (увеличили таймаут)
        with socket.create_connection((parsed.hostname, int(parsed.port)), timeout=5):
            return link
    except: return None

def test_xray_worker(link, white_list, countries, thread_id):
    try:
        parsed = urlparse(link)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        sni = params.get("sni", "").lower()
        pbk = params.get("pbk")
        socks_port = 11000 + thread_id
        
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": socks_port, "protocol": "socks", "settings": {"udp": True}}],
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
        cfg_name = f"tmp_{thread_id}.json"
        with open(cfg_name, "w") as f: json.dump(config, f)
        
        # Запуск Xray
        proc = subprocess.Popen([XRAY_PATH, "-c", cfg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2) # Даем чуть больше времени на старт
        
        success, country_code, latency = False, "UN", 9999
        try:
            st = time.time()
            # Проверка через прокси
            r = requests.get(CHECK_URL, proxies={"http":f"socks5://127.0.0.1:{socks_port}","https":f"socks5://127.0.0.1:{socks_port}"}, timeout=10)
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
            tag = f"{'RDL' if pbk else 'TLS'}-{sni if sni else 'no-sni'}-{country}-{latency}ms".replace(' ', '_')
            return {"link": f"{link.split('#')[0]}#{quote(tag)}", "white": sni in white_list, "latency": latency, "id": f"{parsed.hostname}_{sni}"}
    except: pass
    return None

def main():
    white_list, countries = load_list(SNI_FILE), load_json(COUNTRY_FILE)
    sources = load_list(SOURCES_FILE)
    
    if not sources:
        print("!!! ОШИБКА: Файл sources.txt пуст или не найден!")
        return

    print(f"--- 1. Сбор ссылок из {len(sources)} источников ---")
    raw_links = []
    for url in sources:
        try:
            res = requests.get(url, timeout=15).text
            # Улучшенный Regex
            found = re.findall(r'vless://[^\s"\'<>]+', res)
            raw_links.extend(found)
            print(f"Из {url} взято {len(found)} ссылок")
        except Exception as e:
            print(f"Ошибка при загрузке {url}: {e}")
    
    unique_links = list(set(raw_links))
    total = len(unique_links)
    if total == 0:
        print("!!! ССЫЛОК НЕ НАЙДЕНО. Проверь источники!")
        return
    print(f"Всего уникальных: {total}")

    # ЭТАП 1
    print(f"--- 2. Скрининг портов ({PORT_THREADS} потоков) ---")
    alive_ports = []
    with ThreadPoolExecutor(max_workers=PORT_THREADS) as executor:
        futures = [executor.submit(is_port_open, link) for link in unique_links]
        for f in as_completed(futures):
            res = f.result()
            if res: alive_ports.append(res)
    
    print(f"Порты открыты у {len(alive_ports)} ключей.")
    if not alive_ports:
        print("!!! Ни один порт не ответил. Либо все ключи мертвы, либо GitHub блокирует исходящие.")
        return

    # ЭТАП 2
    print(f"--- 3. Глубокий тест Xray ({XRAY_THREADS} потоков) ---")
    results_normal, results_white, seen_ids = [], [], set()
    
    with ThreadPoolExecutor(max_workers=XRAY_THREADS) as executor:
        futures = [executor.submit(test_xray_worker, link, white_list, countries, i % XRAY_THREADS) for i, link in enumerate(alive_ports)]
        for f in as_completed(futures):
            res = f.result()
            if res and res["id"] not in seen_ids:
                if res["white"]: results_white.append(res)
                else: results_normal.append(res)
                seen_ids.add(res["id"])

    # Сортировка
    results_normal.sort(key=lambda x: x['latency'])
    results_white.sort(key=lambda x: x['latency'])
    
    w_list = [r['link'] for r in results_normal]
    wh_list = [r['link'] for r in results_white]
    
    # ЗАПИСЬ
    print(f"--- 4. Сохранение результатов (Рабочих: {len(w_list + wh_list)}) ---")
    
    with open("working.txt", "w", encoding='utf-8') as f: 
        f.write("\n".join(w_list))
    
    with open("whitelist.txt", "w", encoding='utf-8') as f: 
        f.write("\n".join(wh_list))
    
    if w_list + wh_list:
        combined = "\n".join(w_list + wh_list)
        encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
        with open("sub.txt", "w", encoding='utf-8') as f:
            f.write(encoded)
        print("Файл sub.txt успешно записан.")
    else:
        # Чтобы sub.txt не был старым, очистим его если ничего не нашли
        open("sub.txt", "w").close()
        print("Рабочих ключей 0, файлы очищены.")

if __name__ == "__main__": main()
