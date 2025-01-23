import json
import os
from termcolor import colored
from sql_injection import SQLInjectionScanner
from csrf import CSRFScanner
from directory_traversal import DirectoryTraversalScanner
from xss_scanner import XSSScanner
from colorama import Fore, Style

class WebGuard:
    def __init__(self):
        pass

    def clear_console(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_title(self):
        print(colored(r"""
        
__          ________ ____   _____ _    _         _____  _____  
\ \        / /  ____|  _ \ / ____| |  | |  /\   |  __ \|  __ \ 
 \ \  /\  / /| |__  | |_) | |  __| |  | | /  \  | |__) | |  | |
  \ \/  \/ / |  __| |  _ <| | |_ | |  | |/ /\ \ |  _  /| |  | |
   \  /\  /  | |____| |_) | |__| | |__| / ____ \| | \ \| |__| |
    \/  \/   |______|____/ \_____|\____/_/    \_\_|  \_\_____/ 
                                                                 

        """, 'cyan'))
        print(colored("Welcome to Webguard - Web Vulnerability Scanner", 'yellow'))
        print("-" * 50)

    def display_menu(self):
        print("\nPlease choose what you would like to scan:")
        print(colored("1. Scan for CSRF Vulnerabilities", 'green'))
        print(colored("2. Scan for SQL Injection Vulnerabilities", 'green'))
        print(colored("3. Scan for Directory Traversal Vulnerabilities", 'green'))
        print(colored("4. Scan for XSS Vulnerabilities", 'green'))
        print(colored("5. Full Scan (All Vulnerabilities)", 'green'))
        print(colored("6. Exit", 'red'))
        
        while True:
            choice = input("\nEnter your choice (1/2/3/4/5/6): ")
            if choice in ['1', '2', '3', '4', '5', '6']:
                return choice
            else:
                print(colored("\nInvalid choice! Please try again.", 'red'))

    def full_scan(self, url):
        print(colored("\nStarting Full Scan...\n", 'yellow'))

        scanner = CSRFScanner()
        scanner.csrf_scanner(url)
        csrf_result = "CSRF vulnerabilities found." if len(scanner.results) > 0 else "No CSRF vulnerabilities found."

        sql_injection_scanner = SQLInjectionScanner(url)
        sql_injection_scanner.crawl_and_test()
        sql_injection_result = "SQL injection vulnerabilities found." if sql_injection_scanner.results else "No SQL injection vulnerabilities found."

        dir_traversal_scanner = DirectoryTraversalScanner(url)
        dir_traversal_result = dir_traversal_scanner.scan()

        xss_scanner = XSSScanner(url)
        xss_results = xss_scanner.scan_url()
        
        print(Fore.MAGENTA + "\n[***] Full Scan Report [***]\n" + Style.RESET_ALL)
        
        print(Fore.GREEN + "CSRF Scan Results: " + Style.RESET_ALL)
        print(csrf_result)
        
        print(Fore.GREEN + "\nSQL Injection Scan Results: " + Style.RESET_ALL)
        print(sql_injection_result)
        
        print(Fore.GREEN + "\nDirectory Traversal Scan Results: " + Style.RESET_ALL)
        print(dir_traversal_result or "No Directory Traversal vulnerabilities found.")
        
        print(Fore.GREEN + "\nXSS Scan Results: " + Style.RESET_ALL)
        print(json.dumps(xss_results, indent=4))

    def main(self):
        self.clear_console()
        self.display_title()
        
        url = input("\nEnter the website URL to scan: ").strip()

        while True:
            choice = self.display_menu()

            if choice == '1':
                print(colored("\nStarting CSRF Scan...", 'yellow'))
                scanner = CSRFScanner()
                scanner.csrf_scanner(url)
                scanner.print_final_report()

            elif choice == '2':
                print(colored("\nStarting SQL Injection Scan...", 'yellow'))
                sql_injection_scanner = SQLInjectionScanner(url)
                sql_injection_scanner.crawl_and_test()
                sql_injection_scanner.print_final_report()

            elif choice == '3':
                print(colored("\nStarting Directory Traversal Scan...", 'yellow'))
                dir_traversal_scanner = DirectoryTraversalScanner(url)
                dir_traversal_scanner.scan()

            elif choice == '4':
                print(colored("\nStarting XSS Scan...", 'yellow'))
                xss_scanner = XSSScanner(url)
                results = xss_scanner.scan_url()
                print("Scan Results:")
                print(json.dumps(results, indent=4))

            elif choice == '5':
                self.full_scan(url)

            elif choice == '6':
                print(colored("\nExiting Webguard. Goodbye!", 'red'))
                break

if __name__ == "__main__":
    webguard = WebGuard()
    webguard.main()