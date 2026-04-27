import os
import sys
import json
import requests

API_KEY = "c1f293201ca80aa6308a04d7b87a8249a683812866eb3d2eb55bf9cf89718a16"
DOMAIN = "example.com"

def test_ssl():
    print(f"Testing SSL for {DOMAIN}...")
    headers = {"Authorization": f"TOKEN={API_KEY}"}
    url = f"https://whoisjson.com/api/v1/ssl-cert-check?domain={DOMAIN}"
    try:
        res = requests.get(url, headers=headers, timeout=10)
        print(f"Status Code: {res.status_code}")
        print("Response JSON:")
        print(json.dumps(res.json(), indent=2))
        return res.status_code == 200
    except Exception as e:
        print(f"Error testing SSL: {e}")
        return False

def test_whois():
    print(f"\nTesting WHOIS for {DOMAIN}...")
    headers = {"Authorization": f"TOKEN={API_KEY}"}
    url = f"https://whoisjson.com/api/v1/whois?domain={DOMAIN}&_forceRefresh=1"
    try:
        res = requests.get(url, headers=headers, timeout=10)
        print(f"Status Code: {res.status_code}")
        print("Response JSON:")
        print(json.dumps(res.json(), indent=2))
        return res.status_code == 200
    except Exception as e:
        print(f"Error testing WHOIS: {e}")
        return False

if __name__ == "__main__":
    test_ssl()
    test_whois()
