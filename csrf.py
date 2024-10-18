import requests
from bs4 import BeautifulSoup
import math
from collections import Counter
from urllib.parse import urljoin, urlparse, parse_qs
import time
import logging
from termcolor import colored

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set to store visited URLs to avoid re-scanning
visited_urls = set()
stop_scanning = False  # Flag to control scanning

# Store results for final report
results = []

# Function to calculate Shannon entropy
def calculate_entropy(token):
    if not token:
        return 0
    counter = Counter(token)
    token_length = len(token)
    entropy = 0
    for count in counter.values():
        p_x = count / token_length
        entropy += -p_x * math.log2(p_x)
    return entropy

# Normalize URL by stripping certain query parameters
def normalize_url(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    # Remove parameters that don't affect form submissions, e.g., pic
    params_to_remove = ['pic']  # Add other parameters to ignore as needed
    for param in params_to_remove:
        if param in query_params:
            del query_params[param]

    normalized_query = '&'.join(f"{k}={v[0]}" for k, v in query_params.items())
    normalized_url = parsed_url._replace(query=normalized_query).geturl()
    
    return normalized_url

# Function to extract internal links from a page
def extract_internal_links(soup, base_url):
    links = set()
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(base_url, href)
        if urlparse(base_url).netloc == urlparse(full_url).netloc:
            links.add(full_url)
    return links

# Function to check CSRF vulnerability on a single page
def csrf_scanner(url, entropy_threshold=3.5):
    global stop_scanning
    normalized_url = normalize_url(url)
    
    if normalized_url in visited_urls or stop_scanning:
        return
    visited_urls.add(normalized_url)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            logging.warning(colored(f"Failed to access {url}. Status Code: 404 Not Found", 'yellow'))
            return
        elif response.status_code != 200:
            logging.warning(colored(f"Failed to access {url}. Status Code: {response.status_code}", 'yellow'))
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            logging.info(colored(f"No forms found on {url}", 'cyan'))
        else:
            logging.info(colored(f"Scanning {len(forms)} forms on {url} for CSRF vulnerabilities...", 'cyan'))

        for index, form in enumerate(forms):
            inputs = form.find_all('input')
            csrf_token_found = False

            for input_tag in inputs:
                input_name = input_tag.get('name', '').lower()
                token_value = input_tag.get('value', '')
                if 'csrf' in input_name or 'token' in input_name:
                    csrf_token_found = True
                    token_entropy = calculate_entropy(token_value)
                    logging.info(colored(f"Form {index + 1}: CSRF token found in input field '{input_name}'. Token entropy is {token_entropy:.2f}.", 'green'))
                    if token_entropy >= entropy_threshold:
                        logging.info(colored(f"Form {index + 1}: Token has sufficient entropy. The form is likely secure.", 'green'))
                    else:
                        logging.warning(colored(f"Form {index + 1}: Token entropy is too low! The form may be vulnerable.", 'red'))
                        results.append((url, f"Form {index + 1}: Token entropy is too low! The form may be vulnerable."))
            
            if not csrf_token_found:
                logging.warning(colored(f"Form {index + 1}: No CSRF token found! The form may be vulnerable.", 'red'))
                results.append((url, f"Form {index + 1}: No CSRF token found! The form may be vulnerable."))

        internal_links = extract_internal_links(soup, url)
        for link in internal_links:
            csrf_scanner(link, entropy_threshold)
            if stop_scanning:  # Check if scanning has been stopped after processing each link
                return
            time.sleep(1)  # Rate limiting

    except requests.RequestException as e:
        logging.error(colored(f"Error accessing {url}: {str(e)}", 'red'))

# Function to print the final report
def print_final_report():
    logging.info(colored("\n--- Final Report ---", 'blue'))
    if not results:
        logging.info(colored("No CSRF vulnerabilities found.", 'green'))
    else:
        for url, message in results:
            logging.info(colored(f"{url} - {message}", 'red'))
        logging.info(colored("\nMitigations:", 'blue'))
        logging.info(colored("1. Always use CSRF tokens in forms that perform state-changing actions.", 'yellow'))
        logging.info(colored("2. Ensure CSRF tokens have high entropy and are unique for each session.", 'yellow'))
        logging.info(colored("3. Consider implementing SameSite cookies for additional protection.", 'yellow'))

if __name__ == "__main__":    
    try:
        target_url = input("Enter the base URL to start scanning for CSRF vulnerabilities: ")
        csrf_scanner(target_url)
    except KeyboardInterrupt:
        stop_scanning = True  # Set flag to stop scanning
        logging.info(colored("Scanning stopped by user.", 'yellow'))
    
    print_final_report()
