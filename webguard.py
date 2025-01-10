import json
import os
from termcolor import colored
from sql_injection import crawl_and_test
from csrf import csrf_scanner, print_final_report as csrf_report
from directory_traversal import scan_directory_traversal
from xss_scanner import scan_url, scan_forms_for_xss, get_xss_payloads
from colorama import Fore, Style

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_title():
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

def display_menu():
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

def full_scan(url):
    print(colored("\nStarting Full Scan...\n", 'yellow'))

    csrf_scanner(url)
    csrf_result = "CSRF vulnerabilities found." if len(csrf_report()) > 0 else "No CSRF vulnerabilities found."

    sql_injection_result = crawl_and_test(url)

    dir_traversal_result = scan_directory_traversal(url)

    xss_result = []
    scan_url(url)
    for payload in get_xss_payloads():
        result = scan_forms_for_xss(url, payload)
        xss_result.append(result)
    
    print(Fore.MAGENTA + "\n[***] Full Scan Report [***]\n" + Style.RESET_ALL)
    
    print(Fore.GREEN + "CSRF Scan Results: " + Style.RESET_ALL)
    print(csrf_result)
    
    print(Fore.GREEN + "\nSQL Injection Scan Results: " + Style.RESET_ALL)
    print(sql_injection_result or "No SQL Injection vulnerabilities found.")
    
    print(Fore.GREEN + "\nDirectory Traversal Scan Results: " + Style.RESET_ALL)
    print(dir_traversal_result or "No Directory Traversal vulnerabilities found.")
    
    print(Fore.GREEN + "\nXSS Scan Results: " + Style.RESET_ALL)
    if xss_result:
        for res in xss_result:
            print(res)
    else:
        print("No XSS vulnerabilities found.")

def main():
    clear_console()
    display_title()
    
    url = input("\nEnter the website URL to scan: ").strip()

    while True:
        choice = display_menu()

        if choice == '1':
            print(colored("\nStarting CSRF Scan...", 'yellow'))
            csrf_scanner(url)
            csrf_report()

        elif choice == '2':
            print(colored("\nStarting SQL Injection Scan...", 'yellow'))
            crawl_and_test(url)

        elif choice == '3':
            print(colored("\nStarting Directory Traversal Scan...", 'yellow'))
            scan_directory_traversal(url)

        elif choice == '4':
            print(colored("\nStarting XSS Scan...", 'yellow'))
            results = scan_url(url)
            print("Scan Results:")
            if results['basic']['vulnerable']:
                print(colored("Vulnerable to Basic XSS Attacks:", 'red'))
                for payload in results['basic']['vulnerable']:
                    print(f"  - {payload}")
            else:
                print(colored("Not Vulnerable to Basic XSS Attacks", 'green'))
    
            if results['obfuscated']['vulnerable']:
                print(colored("Vulnerable to Obfuscated XSS Attacks:", 'red'))
                for payload in results['obfuscated']['vulnerable']:
                    print(f"  - {payload}")
            else:
                print(colored("Not Vulnerable to Obfuscated XSS Attacks", 'green'))
    
            for context, context_results in results['context_specific'].items():
                if context_results['vulnerable']:
                    print(colored(f"Vulnerable to {context.capitalize()} XSS Attacks:", 'red'))
                    for payload in context_results['vulnerable']:
                        print(f"  - {payload}")
                else:
                    print(colored(f"Not Vulnerable to {context.capitalize()} XSS Attacks", 'green'))

        elif choice == '5':
            full_scan(url)

        elif choice == '6':
            print(colored("\nExiting Webguard. Goodbye!", 'red'))
            break

if __name__ == "__main__":
    main()