import json
import requests
import sys
from main import *
import base64

#Header file sent to VirusTotal.
headers = {
        "Accept": "application/json",
        "x-apikey": "API KEY HERE"
}

def url_search():
    x = input('Enter URL: ')
    # VT uses base64 unpadded encoding as per RFC 4648, this function changes to base64 and removes padding.
    url_id = base64.urlsafe_b64encode(x.encode()).decode().strip("=")
    url = "https://www.virustotal.com/api/v3/urls/" + url_id
    #Simple get request then store in JSON
    response = requests.request("GET", url, headers=headers).json()
    data = response
    for k, v in data["data"]["attributes"]["last_analysis_results"].items():
        print("{:<30} {:<30}".format(k, str(v["result"])))

def ip_search():
    x = input("Enter IP Address: ")
    ip_id = x
    search_ip = "https://www.virustotal.com/api/v3/ip-address/" + ip_id
    response = requests.request("GET", search_ip, headers=headers)
    data = response.text
    for k, v in data["data"]["attributes"]["last_analysis_results"].items():
        print("{:<30} {:<30}".format(k, str(v["result"])))

def md5_search():
    x = input("Enter MD5: ")
    md5_id = x
    search_md5 = "https://www.virustotal.com/api/v3/file/" + md5_id
    response = requests.request("GET", search_md5, headers=headers).json()
    data = response
    for k, v in data["data"]["attributes"]["last_analysis_results"].items():
        print("{:<30} {:<30}".format(k, str(v["result"])))