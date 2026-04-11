import json, os, re, subprocess, time, requests, base64, random
from urllib.parse import urlparse, parse_qs, quote

# --- НАСТРОЙКИ ---
SNI_FILE = "sni_list.txt"
SOURCES_FILE = "sources.txt"
COUNTRY_FILE = "country_codes.json"
CHECK_URL = "https://www.google.com/generate_204"
SINGBOX_PATH = "./sing-box"
MAX_KEYS_TO_TEST = 200 # Увеличили лимит, GitHub вытянет
# -----------------

def load_list(f):
    if not os.path.exists(f): return []
    with open(f, 'r', encoding='utf-8') as file:
        return [line.strip().lower() for line in file if line.strip() and not line.startswith('#')]

def load_json(f):
    if not os.path.exists(f): return {}
    with open(f, 'r', encoding='utf-8') as file:
        try: return json.load(file)
        except: return {}

def get_country(ip, countries_dict):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=3).json()
        code = resp.get("countryCode")
        return countries_dict.get(code, code) if code else "Unknown"
    except:
        return "Unknown"

def test_key(link, white_list_domains, countries_dict):
    try:
        parsed = urlparse(link)
        if parsed.scheme != 'vless': return None
        
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        sni = params.get("sni", "").lower()
        
        # Конфиг sing-box
        sb_config = {
            "outbounds": [{
                "type": "vless",
                "tag": "proxy",
                "server": parsed.hostname,
                "server_port": int(parsed.port),
                "uuid": parsed.username,
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": params.get("pbk"), "short_id": params.get("sid")} if params.get("pbk") else None
                }
            }],
            "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 10808}]
        }
        
        with open("temp_config.json", "w") as f:
            json.dump(sb_config, f)
        
        proc = subprocess.Popen([SINGBOX_PATH, "run", "-c", "temp_config.json"], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        start_t = time.time()
        success = False
        latency = 9999
        try:
            proxies = {"http": "socks5://127.0.0.1:10808", "https": "socks5://127.0.0.1:10808"}
            r = requests.get(CHECK_URL, proxies=proxies, timeout=5)
            if r.status_code in [200, 204]:
                latency = int((time.time() - start_t) * 1000)
                success = True
        except:
            pass
        
        proc.terminate()
        proc.wait()

        if success:
            country = get_country(parsed.hostname, countries_dict)
            clean_link = link.split('#')[0]
            new_name = f"vless-{sni if sni else 'no-sni'}-{country}-{latency}ms".replace(' ', '_')
            return {
                "link": f"{clean_link}#{quote(new_name)}",
                "white": sni in white_list_domains,
                "latency": latency,
                "server": parsed.hostname,
                "sni": sni
            }
        return None
    except:
        return None

def main():
    white_list = load_list(SNI_FILE)
    sources = load_list(SOURCES_FILE)
    countries_dict = load_json(COUNTRY_FILE)
    
    print("--- Сбор и перемешивание ключей ---")
    all_links = []
    for url in sources:
        try:
            res = requests.get(url, timeout=10).text
            all_links.extend(re.findall(r'vless://[^\s]+', res))
        except: continue

    unique_links = list(set(all_links))
    random.shuffle(unique_links) # ГАЗ! Каждый раз разные ключи в тесте
    
    results_normal = []
    results_white = []
    seen_ips = set() # Для дедупликации по парам IP+SNI

    to_test = unique_links[:MAX_KEYS_TO_TEST]
    print(f"Тестируем {len(to_test)} ключей...")

    for i, link in enumerate(to_test):
        print(f"[{i+1}/{len(to_test)}] Проверка...", end='\r')
        res = test_key(link, white_list, countries_dict)
        
        if res:
            # Умная дедупликация: один сервер + один SNI = одна запись
            dup_id = f"{res['server']}_{res['sni']}"
            if dup_id not in seen_ips:
                if res["white"]: results_white.append(res)
                else: results_normal.append(res)
                seen_ips.add(dup_id)

    # СОРТИРОВКА ПО СКОРОСТИ (Latency)
    results_normal.sort(key=lambda x: x['latency'])
    results_white.sort(key=lambda x: x['latency'])

    # Сохранение в файлы (только ссылки)
    working_list = [r['link'] for r in results_normal]
    white_list_final = [r['link'] for r in results_white]

    with open("working.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(working_list))
    with open("whitelist.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(white_list_final))
    
    # Base64 подписка (все вместе)
    all_working = working_list + white_list_final
    with open("sub.txt", "w", encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(all_working).encode()).decode())

    print(f"\nИтог: Обычные: {len(working_list)} | Белые: {len(white_list_final)}")

if __name__ == "__main__":
    main()
