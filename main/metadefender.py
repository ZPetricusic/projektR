import os
import json
import requests
import time
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("METADEFENDER_API")
API_DELAY = int(os.getenv("METADEFENDER_API_DELAY"))

# Defining the api-endpoint
url = "https://api.metadefender.com/v4/ip/"

headers = {
 "apikey": API_KEY,
 "Content-Type": "application/json"
}

def MetadefenderBulkAnalyse(ip_list):
    # get the JSON string for sending
    payload = json.dumps({"address":ip_list})
    
    print(
		f"[*] Sleeping for {API_DELAY} seconds due to the obligatory API delay for this plan.."
	)
    time.sleep(API_DELAY)

    print(f"[*] Querying Metadefender for info on {len(ip_list)} IP address{'es' if len(ip_list) > 1 else ''}")

    response = requests.post(url, headers=headers, data=payload)

    decodedResponse = json.loads(response.text)["data"]

    # create a list with all the formatted objects
    tmp = {}

    for i in decodedResponse:
        tmp.update({i["address"] : {"Metadefender_detections" : f'{i["lookup_results"]["detected_by"]}/{len(i["lookup_results"]["sources"])}'}})

    return tmp