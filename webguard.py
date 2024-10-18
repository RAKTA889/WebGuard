import os
from termcolor import colored
from sql_injection import crawl_and_test  # Ensure this is correct
from csrf import csrf_scanner, print_final_report as csrf_report  # Ensure csrf.py is present and correct
from directory_traversal import scan_directory_traversal  # Import the directory traversal module
from xss_scanner import scan_url, scan_forms_for_xss, get_xss_payloads  # Import XSS scanning functions
from colorama import Fore, Style

# Function to clear console for a fresh display
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to display Webguard ASCII art
def display_title():
    print(colored(r"""
    
__          ________ ____   _____ _    _         _____  _____  
\ \        / /  ____|  _ \ / ____| |  | |  /\   |  __ \|  __ \ 
 \ \  /\  / /| |__  | |_) | |  __| |  | | /  \  | |__) | |  | |
  \ \/  \/ / |  __| |  _ <| | |_ | |  | |/ /\ \ |  _  /| |  | |
   \  /\  /  | |____| |_) | |__| | |__| / ____ \| | \ \| |__| |
    \/  \/   |______|____/ \_____|\____/_/    \_\_|  \_\_____/ 
                                                                 

    """, 'cyan'))  # Using raw string to avoid escape sequence warning
    print(colored("Welcome to Webguard - Web Vulnerability Scanner", 'yellow'))
    print("-" * 50)

# Function to display menu and handle choices
def display_menu():
    print("\nPlease choose what you would like to scan:")
    print(colored("1. Scan for CSRF Vulnerabilities", 'green'))
    print(colored("2. Scan for SQL Injection Vulnerabilities", 'green'))
    print(colored("3. Scan for Directory Traversal Vulnerabilities", 'green'))
    print(colored("4. Scan for XSS Vulnerabilities", 'green'))
    print(colored("5. Full Scan (All Vulnerabilities)", 'green'))  # Full Scan option
    print(colored("6. Exit", 'red'))
    
    choice = input("\nEnter your choice (1/2/3/4/5/6): ")
    return choice

# Function to perform a full scan
def full_scan(url):
    print(colored("\nStarting Full Scan...\n", 'yellow'))

    # CSRF Scan
    print(Fore.CYAN + "[1/4] Running CSRF scan..." + Style.RESET_ALL)
    csrf_scanner(url)
    csrf_result = "CSRF vulnerabilities found." if len(csrf_report()) > 0 else "No CSRF vulnerabilities found."

    # SQL Injection Scan
    print(Fore.CYAN + "[2/4] Running SQL Injection scan..." + Style.RESET_ALL)
    sql_injection_result = crawl_and_test(url)

    # Directory Traversal Scan
    print(Fore.CYAN + "[3/4] Running Directory Traversal scan..." + Style.RESET_ALL)
    dir_traversal_result = scan_directory_traversal(url)

    # XSS Scan
    print(Fore.CYAN + "[4/4] Running XSS scan..." + Style.RESET_ALL)
    xss_result = []
    scan_url(url)  # URL-based XSS
    for payload in get_xss_payloads():
        result = scan_forms_for_xss(url, payload)  # Form-based XSS
        xss_result.append(result)
    
    # Final Report
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

# Main function
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
            scan_url(url)
            for payload in get_xss_payloads():
                scan_forms_for_xss(url, payload)

        elif choice == '5':
            full_scan(url)  # Perform full scan

        elif choice == '6':
            print(colored("\nExiting Webguard. Goodbye!", 'red'))
            break

        else:
            print(colored("\nInvalid choice! Please try again.", 'red'))

if __name__ == "__main__":
    main()
