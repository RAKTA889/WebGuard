import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException, InvalidElementStateException
import logging
import argparse
import time

# Basic GET request
def get_request(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response
        else:
            print(f"Failed to fetch {url}. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
    return None

# XSS Payloads
def get_xss_payloads():
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "><script>alert('XSS')</script>"
    ]

# Inject payload into URL
def inject_payload(url, payload):
    if "?" in url:
        return url + "&payload=" + payload
    else:
        return url + "?payload=" + payload

# Analyze server response for XSS
def analyze_response(response, payload):
    if payload in response.text:
        if "<script>" in response.text or "alert(" in response.text:
            return f"XSS vulnerability found! Payload executed: {payload}"
        else:
            return f"Payload reflected but not executed: {payload}"
    else:
        return f"No XSS found with payload: {payload}"

# Logging setup
logging.basicConfig(filename='xss_scan_report.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to log scan results
def log_scan_result(url, payload, result):
    with open("xss_scan_report.log", "a") as log_file:
        log_file.write(f"{url} | Payload: {payload} | Result: {result}\n")

# Scan for DOM-based XSS
def scan_dom_xss(url, payload):
    print(f"Scanning {url} for DOM-based XSS vulnerabilities with payload: {payload}...")

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--window-size=1920x1080")

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
    driver.get(url)

    try:
        injected_url = inject_payload(url, payload)
        driver.get(injected_url)

        # Check if payload is present in the page
        if payload in driver.page_source:
            # Try executing JavaScript to detect if the payload triggers an alert
            try:
                driver.execute_script("return alert()")
                print(f"DOM-based XSS vulnerability found with payload: {payload}")
                return f"DOM-based XSS vulnerability found with payload: {payload}"
            except Exception as e:
                print(f"Payload reflected but no alert triggered: {payload}")
                return f"Payload reflected but no alert triggered: {payload}"
        else:
            return f"No DOM-based XSS found with payload: {payload}"
    except Exception as e:
        print(f"Error scanning DOM: {e}")
    finally:
        driver.quit()


# Scan forms for XSS
def scan_forms_for_xss(url, payload):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--window-size=1920x1080")

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
    
    try:
        driver.get(url)
        print(f"Scanning URL: {url}")
        forms = driver.find_elements(By.TAG_NAME, 'form')

        if forms:
            print(f"Found {len(forms)} forms on the page.")
            for form_index, form in enumerate(forms, start=1):
                print(f"Processing form #{form_index}")
                input_elements = form.find_elements(By.TAG_NAME, 'input')

                for input_element in input_elements:
                    try:
                        attempts = 3
                        while attempts > 0:
                            try:
                                WebDriverWait(driver, 10).until(
                                    EC.element_to_be_clickable(input_element)
                                )
                                if input_element.is_enabled() and input_element.is_displayed():
                                    input_element.clear()
                                    input_element.send_keys(payload)
                                    print(f"Injected payload into input field.")
                                else:
                                    print(f"Input element not interactable: {input_element}. Skipping.")
                                break

                            except StaleElementReferenceException:
                                print(f"Stale element reference, retrying... Attempts left: {attempts - 1}")
                                input_element = form.find_element(By.TAG_NAME, 'input')
                                attempts -= 1

                    except TimeoutException:
                        print(f"Input element not interactable after waiting. Skipping to next.")
                        continue

                    except InvalidElementStateException:
                        print(f"Invalid element state, cannot interact with this input.")
                        continue

                print("Submitting form...")
                form.submit()
                time.sleep(2)

                if payload in driver.page_source:
                    result = f"Potential XSS detected in form #{form_index} on {url} with payload {payload}"
                    print(result)
                    log_scan_result(url, payload, result)
                else:
                    result = f"No XSS detected in form #{form_index} on {url} with payload {payload}"
                    print(result)
                    log_scan_result(url, payload, result)

        else:
            print("No forms found on the page.")

    except Exception as e:
        print(f"Error occurred during scanning: {e}")

    finally:
        driver.quit()

# Main scanning function
def scan_url(url):
    print(f"Scanning {url} for XSS vulnerabilities...")

    response = get_request(url)

    if response:
        payloads = get_xss_payloads()
        for payload in payloads:
            print(f"\nTesting payload: {payload}")
            injected_url = inject_payload(url, payload)
            print(f"Injected URL: {injected_url}")

            response = get_request(injected_url)
            if response:
                result = analyze_response(response, payload)
                log_scan_result(url, payload, result)

            dom_result = scan_dom_xss(url, payload)
            log_scan_result(url, payload, dom_result)
    else:
        print("Failed to fetch the URL.")

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="XSS Vulnerability Scanner")
    parser.add_argument('--url', type=str, required=True, help="URL to scan for XSS vulnerabilities")
    parser.add_argument('--payloads', type=str, nargs='+', help="Custom XSS payloads")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    if args.payloads:
        payloads = args.payloads
    else:
        payloads = get_xss_payloads()

    for payload in payloads:
        scan_url(args.url)
        scan_forms_for_xss(args.url, payload)
