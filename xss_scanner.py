import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging
import time
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class XSSScanner:
    def __init__(self, url):
        self.url = url

    def get_request(self, url, delay=0.2, timeout=10, verify=True):
        try:
            response = requests.get(url, timeout=timeout, verify=verify)
            time.sleep(delay)  # Rate limiting
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching {url}: {e}")
            return None

    def load_payloads(self, file_path="payloads.json"):
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

    def inject_payload(self, url, payload):
        if "?" in url:
            return url + "&payload=" + payload
        else:
            return url + "?payload=" + payload

    def analyze_response(self, response, payload):
        if payload in response.text:
            if "<script>" in response.text or "alert(" in response.text or "onerror=" in response.text:
                return {'status': 'vulnerable', 'payload': payload}
            else:
                return {'status': 'reflected', 'payload': payload}
        return {'status': 'not_vulnerable', 'payload': payload}

    def scan_url(self, delay=0.2):
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
        
        payloads = self.load_payloads()
        
        # Test basic payloads
        for payload in payloads.get('basic', []):
            injected_url = self.inject_payload(self.url, payload)
            response = self.get_request(injected_url, delay)
            if response:
                result = self.analyze_response(response, payload)
                results['basic'][result['status']].append(payload)

        # Test obfuscated payloads
        for payload in payloads.get('obfuscated', []):
            injected_url = self.inject_payload(self.url, payload)
            response = self.get_request(injected_url, delay)
            if response:
                result = self.analyze_response(response, payload)
                results['obfuscated'][result['status']].append(payload)

        # Test context-specific payloads
        for context, context_payloads in payloads.get('context_specific', {}).items():
            for payload in context_payloads:
                injected_url = self.inject_payload(self.url, payload)
                response = self.get_request(injected_url, delay)
                if response:
                    result = self.analyze_response(response, payload)
                    results['context_specific'][context][result['status']].append(payload)

        return results

    def scan_forms_for_xss(self, url, payload):
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
                result = self.analyze_response(response, payload)
                if result['status'] == 'vulnerable':
                    return f"XSS vulnerability found in form at {form_action}"
        except Exception as e:
            logging.error(f"Error scanning forms for XSS: {e}")
        return f"No XSS vulnerability found in form at {url}"

    def get_xss_payloads(self):
        return self.load_payloads().get('basic', [])

# Main function to execute the scanner
if __name__ == "__main__":
    target_url = input("Enter the URL to scan for XSS vulnerabilities: ")
    scanner = XSSScanner(target_url)
    results = scanner.scan_url()
    print("Scan Results:")
    print(json.dumps(results, indent=4))
    
    # Get a list of XSS payloads
    payloads = scanner.get_xss_payloads()
    
    # Scan forms for XSS vulnerabilities
    for payload in payloads:
        result = scanner.scan_forms_for_xss(target_url, payload)
        print(result)