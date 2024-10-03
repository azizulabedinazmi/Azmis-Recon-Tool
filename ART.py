import subprocess, platform, requests, socket, whois, signal, sys, getpass
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from colorama import init, Fore
import pyfiglet

init(autoreset=True)

def signal_handler(_signal, _):
    print(Fore.RED + "\nExiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
if platform.system().lower() != 'windows':
    signal.signal(signal.SIGTSTP, signal_handler)

def print_ascii_art(text, color=Fore.GREEN):
    print(color + pyfiglet.figlet_format(text))

def traceroute(domain):
    print_ascii_art("Traceroute", Fore.CYAN)
    command = ['tracert', domain] if platform.system().lower() == 'windows' else ['traceroute', domain]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in iter(process.stdout.readline, ''):
            print(Fore.CYAN + line, end='')
            parts = line.split()
            if parts:
                ip = parts[-1].strip('()')
                if is_valid_ip(ip):
                    fetch_ip_info(ip)
        process.stdout.close()
        process.wait()
    except FileNotFoundError:
        print(Fore.RED + "Traceroute command not found.")

def is_valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def fetch_ip_info(ip):
    try:
        data = requests.get(f"https://ipinfo.io/{ip}/json").json()
        print(Fore.GREEN + f"IP: {ip}\nISP: {data.get('org', 'N/A')}\nLocation: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}\nHostname: {data.get('hostname', 'N/A')}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error fetching IP info: {e}")

def nslookup(domain):
    print_ascii_art("NSLookup", Fore.CYAN)
    try:
        result = subprocess.run(['nslookup', domain], capture_output=True, text=True)
        print(Fore.CYAN + result.stdout)
    except FileNotFoundError:
        print(Fore.RED + "nslookup command not found.")

def check_http_headers(url):
    print_ascii_art("HTTP Headers", Fore.CYAN)
    try:
        headers = requests.get(url).headers
        cache_headers = {k: v for k, v in headers.items() if 'cache' in k.lower() or 'via' in k.lower()}
        if cache_headers:
            print(Fore.GREEN + "Cache-related headers found:")
            for header, value in cache_headers.items():
                print(Fore.GREEN + f"{header}: {value}")
        else:
            print(Fore.YELLOW + "No cache-related headers found.")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error fetching HTTP headers: {e}")

def get_isp_info():
    print_ascii_art("ISP Info", Fore.CYAN)
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        print(Fore.GREEN + f"Your local IP address: {local_ip}")
    except socket.error as e:
        print(Fore.RED + f"Error fetching IP information: {e}")

def get_whois_info(domain):
    print_ascii_art("WHOIS Info", Fore.CYAN)
    try:
        whois_info = whois.whois(domain)
        print(Fore.GREEN + f"Domain Name: {whois_info.domain_name}\nRegistrar: {whois_info.registrar}\nWHOIS Server: {whois_info.whois_server}\nCreation Date: {whois_info.creation_date}\nExpiration Date: {whois_info.expiration_date}\nName Servers: {whois_info.name_servers}\nStatus: {whois_info.status}\nEmails: {whois_info.emails}")
    except Exception as e:
        print(Fore.RED + f"Error fetching WHOIS information: {e}")

def port_scan(domain):
    print_ascii_art("Port Scan", Fore.CYAN)
    try:
        ip = socket.gethostbyname(domain)
        scan_type = input(Fore.YELLOW + "Enter scan type (1 for basic, 2 for all): ").strip()
        ports = range(1, 65536) if scan_type == '2' else [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 20, 69, 123, 161, 162, 389, 636, 989, 990, 993, 995, 1723, 3306, 5432, 5900, 8080, 8443]
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, [ip] * len(ports), ports)
    except socket.error as e:
        print(Fore.RED + f"Error resolving domain to IP: {e}")

def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        if sock.connect_ex((ip, port)) == 0:
            try:
                service_name = socket.getservbyport(port)
            except OSError:
                service_name = "Unknown"
            print(Fore.GREEN + f"Port {port} is open on {ip} (Service: {service_name})")

def fetch_site_title(url):
    print_ascii_art("Site Title", Fore.CYAN)
    try:
        soup = BeautifulSoup(requests.get(url).text, 'html.parser')
        print(Fore.GREEN + f"Site Title: {soup.title.string if soup.title else 'N/A'}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error fetching site title: {e}")

def detect_web_server(url):
    print_ascii_art("Web Server", Fore.CYAN)
    try:
        server = requests.get(url).headers.get('Server', 'N/A')
        print(Fore.GREEN + f"Web Server: {server}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error detecting web server: {e}")

def detect_cms(url):
    print_ascii_art("CMS Detection", Fore.CYAN)
    try:
        response = requests.get(url).text
        if 'wp-content' in response:
            print(Fore.GREEN + "CMS: WordPress")
        elif 'Joomla' in response:
            print(Fore.GREEN + "CMS: Joomla")
        else:
            print(Fore.YELLOW + "CMS: Unknown")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error detecting CMS: {e}")

def check_cloudflare(url):
    print_ascii_art("Cloudflare Check", Fore.CYAN)
    try:
        if 'cloudflare' in requests.get(url).headers.get('Server', '').lower():
            print(Fore.GREEN + "Site is behind Cloudflare")
        else:
            print(Fore.YELLOW + "Site is not behind Cloudflare")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error checking Cloudflare: {e}")

def fetch_robots_txt(url):
    print_ascii_art("Robots.txt", Fore.CYAN)
    try:
        response = requests.get(f"{url}/robots.txt")
        if response.status_code == 200:
            print(Fore.GREEN + "robots.txt content:\n" + response.text)
        else:
            print(Fore.YELLOW + "robots.txt not found")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error fetching robots.txt: {e}")

def grab_banners(ip):
    print_ascii_art("Banner Grabbing", Fore.CYAN)
    try:
        print(Fore.GREEN + f"Banner: {requests.get(f'http://{ip}').headers.get('Server', 'N/A')}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error grabbing banner: {e}")

def sub_domain_scanner(domain):
    print_ascii_art("Subdomain Scanner", Fore.CYAN)
    try:
        response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if response.status_code == 429:
            print(Fore.RED + "API count exceeded - Increase Quota with Membership")
            return
        for subdomain in response.text.split('\n'):
            print(Fore.GREEN + subdomain)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error scanning sub-domains: {e}")

def reverse_ip_lookup(domain):
    print_ascii_art("Reverse IP Lookup", Fore.CYAN)
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={domain}")
        if response.status_code == 429:
            print(Fore.RED + "API count exceeded - Increase Quota with Membership")
            return
        for ip in response.text.split('\n'):
            if is_valid_ip(ip):
                print(Fore.GREEN + ip)
                detect_cms(f"http://{ip}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error performing reverse IP lookup: {e}")

def bloggers_view(url):
    print_ascii_art("Bloggers View", Fore.CYAN)
    try:
        response = requests.get(url)
        print(Fore.GREEN + f"HTTP Response Code: {response.status_code}")
        fetch_site_title(url)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error fetching bloggers view: {e}")

def wordpress_scan(url):
    print_ascii_art("WordPress Scan", Fore.CYAN)
    try:
        if 'wp-content' in requests.get(url).text:
            print(Fore.GREEN + "WordPress site detected")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error performing WordPress scan: {e}")

def sensitive_files_crawling(url):
    print_ascii_art("Sensitive Files", Fore.CYAN)
    try:
        for file in ['.env', 'config.php', 'wp-config.php', '.htaccess']:
            if requests.get(f"{url}/{file}").status_code == 200:
                print(Fore.RED + f"Sensitive file found: {file}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error crawling for sensitive files: {e}")

def version_detection(url):
    print_ascii_art("Version Detection", Fore.CYAN)
    try:
        print(Fore.GREEN + f"Server Version: {requests.get(url).headers.get('Server', 'N/A')}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error detecting version: {e}")

def crawler(url):
    print_ascii_art("Crawler", Fore.CYAN)
    try:
        soup = BeautifulSoup(requests.get(url).text, 'html.parser')
        for link in [a['href'] for a in soup.find_all('a', href=True)]:
            print(Fore.GREEN + link)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error performing web crawling: {e}")

def mx_lookup(domain):
    print_ascii_art("MX Lookup", Fore.CYAN)
    try:
        result = subprocess.run(['nslookup', '-type=mx', domain], capture_output=True, text=True)
        print(Fore.CYAN + result.stdout)
    except FileNotFoundError:
        print(Fore.RED + "nslookup command not found.")

def all_scan(domain):
    print_ascii_art("All Scan", Fore.CYAN)
    url = f"http://{domain}"
    traceroute(domain)
    nslookup(domain)
    check_http_headers(url)
    get_isp_info()
    get_whois_info(domain)
    port_scan(domain)
    fetch_site_title(url)
    detect_web_server(url)
    detect_cms(url)
    check_cloudflare(url)
    fetch_robots_txt(url)
    grab_banners(domain)
    sub_domain_scanner(domain)
    reverse_ip_lookup(domain)
    bloggers_view(url)
    wordpress_scan(url)
    sensitive_files_crawling(url)
    version_detection(url)
    crawler(url)
    mx_lookup(domain)

def login():
    print_ascii_art("Login", Fore.CYAN)
    username = input(Fore.YELLOW + "Enter username: ").strip()
    password = getpass.getpass(Fore.YELLOW + "Enter password: ").strip()
    # Replace with your actual username and password check
    if username == "azmi" and password == "azmi":
        print(Fore.GREEN + "Login successful!")
        return True
    else:
        print(Fore.RED + "Invalid username or password.")
        return False

def main():
    print_ascii_art("Azmi's Recon Tool", Fore.CYAN)
    if not login():
        return

    features = {
        '1': traceroute, '2': nslookup, '3': check_http_headers, '4': get_isp_info, '5': get_whois_info,
        '6': port_scan, '7': fetch_site_title, '8': detect_web_server, '9': detect_cms, '10': check_cloudflare,
        '11': fetch_robots_txt, '12': grab_banners, '13': sub_domain_scanner,
        '14': reverse_ip_lookup, '15': bloggers_view, '16': wordpress_scan,
        '18': sensitive_files_crawling, '19': version_detection, '20': crawler, '21': mx_lookup, '22': all_scan
    }

    while True:
        print(Fore.YELLOW + "Select a feature to run:")
        for key, value in features.items():
            print(Fore.YELLOW + f"{key}: {value.__name__.replace('_', ' ').title()}")
        print(Fore.YELLOW + "0: Exit")

        choice = input(Fore.YELLOW + "Enter your choice: ").strip()
        if choice == '0':
            print(Fore.RED + "Exiting...")
            break

        if choice in features:
            if choice in ['1', '2', '5', '6', '13', '14', '21', '22']:
                domain = input(Fore.YELLOW + "Enter the domain: ").strip()
                domain = urlparse(domain).netloc or domain
                features[choice](domain)
            elif choice in ['3', '7', '8', '9', '10', '11', '12', '15', '16', '17', '18', '19', '20']:
                url = input(Fore.YELLOW + "Enter the URL: ").strip()
                features[choice](url)
            elif choice == '4':
                features[choice]()
        else:
            print(Fore.RED + "Invalid choice. Please enter a valid number.")

if __name__ == "__main__":
    main()
