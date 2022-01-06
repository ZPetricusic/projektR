import os
import json
import httpx
import time
from urllib.parse import urlparse
from dotenv import load_dotenv
from auxiliaries import buildEndpoint

load_dotenv()

API_KEY = os.getenv("GSB_API")
GSB_API_DELAY = os.getenv("GSB_API_DELAY")
CLIENT_ID = os.getenv("GSB_CLIENT_ID")
CLIENT_VERSION = os.getenv("GSB_CLIENT_VERSION")
CHUNKS = 500  # max number of URLs sent for analysis at a time
GSB_SCORE_POSITIVE = 1  # since the GSB verdict can only be true or false
GSB_SCORE_NEGATIVE = 0  # the score can only be 1 or 0 for GSB


def createGSBRequestFromTemplate(url_chunk):
	threatEntriesString = ""

	# create the {"url": "http://www.urltocheck1.org/"} string for each URL
	domain = list(url_chunk.keys())[0]
	for endpoint in url_chunk[domain]:
		threatEntriesString += f'{{"url": "{domain}{endpoint}"}},'

	# cut off the trailing comma
	threatEntriesString = threatEntriesString[:-1]

	# template modified from GSB API docs
	data = f"""{{
		"client": {{
		"clientId": "{CLIENT_ID}",
		"clientVersion": "{CLIENT_VERSION}"
		}},
		"threatInfo": {{
		"threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
		"platformTypes":    ["ANY_PLATFORM"],
		"threatEntryTypes": ["URL"],
		"threatEntries": [
			{threatEntriesString}
		]
		}}
	}}"""

	return json.loads(data)


async def GSBanalyse(data, domain):

	# build the URL
	api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

	# since we can only run 10,000 queries a day we must sleep for approximately 10 seconds per query
	print(
		f"[*] Sleeping for {GSB_API_DELAY} seconds due to the obligatory API delay for this plan.."
	)
	time.sleep(int(GSB_API_DELAY))

	print(
		f"[*] Querying {len(data['threatInfo']['threatEntries'])} URL{f's' if len(data['threatInfo']['threatEntries']) > 1 else ''} for domain '{domain}'"
	)

	async with httpx.AsyncClient() as client:
		# the httpx library automatically converts the header to app/json
		r = httpx.post(api_url, json=data)
		return URLverdict_GSB(r.json())


# analyse the results and give a final verdict
def URLverdict_GSB(GSB_data):
	malicious_endpoints = []
	# in case there are any matches in the provided data
	if len(GSB_data) > 0:
		for match in GSB_data["matches"]:
			# get the URL in question from the results
			current_endpoint = buildEndpoint(match["threat"]["url"])
			# grade the matching URL with a positive score
			malicious_endpoints.append(current_endpoint)
	return malicious_endpoints
