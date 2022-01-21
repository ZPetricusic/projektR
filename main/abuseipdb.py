import os
import json
import requests
import time
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API")
API_DELAY = int(os.getenv("ABUSEIPDB_API_DELAY"))

# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/check'

headers = {
    'Accept': 'application/json',
    'Key': API_KEY
}

def AbuseAnalyse(ip):
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    print(
		f"[*] Sleeping for {API_DELAY} seconds due to the obligatory API delay for this plan.."
	)
    time.sleep(API_DELAY)

    print(f"[*] Querying AbuseIPDB for info on {ip}")

    # query the IP address
    response = requests.get(url, headers=headers, params = querystring)
    decodedResponse = json.loads(response.text)["data"]

    return {"AbuseIPDB_score" : {
        "abuseConfidenceScore" : decodedResponse["abuseConfidenceScore"] if "abuseConfidenceScore" in decodedResponse else 0,
        "countryCode" : decodedResponse["countryCode"] if "countryCode" in decodedResponse else "N/A",
        "usageType" : decodedResponse["usageType"] if "usageType" in decodedResponse else "N/A",
        "isp" : decodedResponse["isp"]  if "isp" in decodedResponse else "N/A",
        "lastReportedAt" : decodedResponse["lastReportedAt"] if "lastReportedAt" in decodedResponse else "N/A",
        "numberOfReports" : len(decodedResponse["reports"]) if "reports" in decodedResponse else 0
    }}