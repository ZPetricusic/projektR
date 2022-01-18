import sys
import asyncio
import socket
from gsb import *
from ioc import *
from shodan_io import *
from auxiliaries import *


async def main():

	data_file, blacklist_file = loadFiles()

	final_scores = {
		"results" : []
	}

	# starting stage 1
	printBanner("STAGE 1 - Filtering and formatting the crawler data")

	try:
		# build the wanted JSON output
		final_scores["results"] = buildFinalJSON(data_file) 
	except Exception as e:
		print(e)
		sys.exit(1)

	# starting stage 2
	printBanner("STAGE 2 - Analyzing the dataset")

	printBanner("STAGE 2.1 - Google Safe Browsing Analysis")

	# intermediary scores
	GSB_malicious_endpoints = []

	# perform a chunkified GSB analysis for every endpoint
	# of every domain
	for domain in final_scores["results"].keys(): 
		# chunkify the endpoints for this domain 
		# into lists of gsb.CHUNKS
		url_chunks = []
		current_chunk = []

		# add every endpoint to the chunks
		endpoint_data_list = final_scores["results"][domain]["endpoint_data"]
		for idx, endpoint in enumerate(endpoint_data_list):
			# e.g. www.fer.unizg.hr : [/login?secerror, ...]
			current_chunk.append(f"{list(endpoint.keys())[0]}")
			# go until we reach the max chunk size or the end of the list
			if len(current_chunk) >= CHUNKS or idx + 1 == len(endpoint_data_list):
				url_chunks.append({domain : current_chunk.copy()}) # send a copy for pass-by-ref reasons
				# reset the chunk
				current_chunk.clear()
				current_chunk = []

		# after filtering the crawler data use the in-memory set to run the tests
		for url_chunk in url_chunks:
			# start with GSB checks
			data = createGSBRequestFromTemplate(url_chunk)
			try:
				GSB_malicious_endpoints = await GSBanalyse(
				    data, domain
				)	
			except Exception as e:
				print(e)
				sys.exit(1)
		
		# update the final JSON with GSB results
		for endpoint in endpoint_data_list:
			endpoint_from_key = list(endpoint.keys())[0]
			# update the first key, the endpoint
			endpoint[endpoint_from_key].update({"scores" : {
				# 1 if malicious, 0 otherwise
				"GSB_SCORE" : GSB_SCORE_POSITIVE if endpoint_from_key in GSB_malicious_endpoints else GSB_SCORE_NEGATIVE
			}})

	print("\n[✓] Successfully analysed URLs using Google Safe Browsing")

	# check the filtered IP addresses with the blacklist.txt for well-known IOCs
	printBanner("STAGE 2.2 - Comparing IP addresses with local IP blacklist")

	# get all the IP addresses for each domain
	for domain in final_scores["results"].keys():
		# all the IPs for each domain
		ip_data_list = []
		[ip_data_list.append(list(x.keys())[0]) for x in final_scores["results"][domain]["ip_data"]]

		IOC_malicious_IPs = []
		try:
			# compare to local blacklist file for well-known IOCs
			IOC_malicious_IPs = IOCanalyse(ip_data_list, blacklist_file)
		except Exception as e:
			print(e)
			sys.exit(1)


	# update the final JSON with IOC results
		for ip in final_scores["results"][domain]["ip_data"]:
			# update the IP
			ip_from_key = list(ip.keys())[0]
			ip[ip_from_key].update({"scores" : {
				# 1 if malicious, 0 otherwise
				"IOC_SCORE" : IOC_SCORE_POSITIVE if ip_from_key in IOC_malicious_IPs else IOC_SCORE_NEGATIVE
			}})

	print("\n[✓] Successfully compared IP list with well-known IOCs")
	
	printBanner("STAGE 2.3 - Analysing IP addresses using Shodan")

	for domain in final_scores["results"].keys():
		# send each IP to Shodan
		for ip in final_scores["results"][domain]["ip_data"]:
			try:
				ip[list(ip.keys())[0]]["scores"].update(ShodanAnalyse(ip))
			except Exception as e:
				print(e)
			# print(final_scores["results"][domain]["ip_data"])
			# final_scores["results"][domain]["ip_data"][list(ip.keys())[0]]["scores"].update(ShodanAnalyse(ip))

	print("\n[✓] Successfully analysed IP addresses using Shodan")

	with open("analysis.json", "w") as out_file:
		out_file.write(json.dumps(final_scores))

if __name__ == "__main__":
	asyncio.run(main())
