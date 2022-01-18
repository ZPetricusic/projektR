import os
import socket
import time
from math import atan, pi
from dotenv import load_dotenv
from shodan import Shodan

SHODAN_RISKY_PORT = "TRUE"
SHODAN_SAFE_PORT = "FALSE"
SHODAN_CRITICAL_VULN = 3
SHODAN_MEDIUM_VULN = 2
SHODAN_LOW_VULN = 1
SHODAN_VULN_COEFFICIENT = 0.9
SHODAN_RISKY_PORT_COEFFICIENT = 0.1


# load .env file
load_dotenv()

# initialize the API
API_KEY = os.getenv('SHODAN_API')
api = Shodan(API_KEY)

# delay
SHODAN_API_DELAY = int(os.getenv("SHODAN_API_DELAY"))

def ShodanAnalyse(ip):
    # sleep to adjust to the request limiter
    time.sleep(SHODAN_API_DELAY)

    # get the info
    results = api.host(ip)
    shodan_score = {"shodan_score" : {
        "ports" : {}, # port numbers : {risky_port : "true/false", product : "product", cpe2.3: "cpe2.3"}
        "vulnerabilities" : {}, # CVEs : cvss
        "last_update" : "update_date",
        "os" : "os_ver", # host OS
        "verdict" : "percentage" # number
    }}

    cve_count = 0
    cvss_total = 0.0

    # start the checks
    # check the ports
    ports = results["ports"]
    risky_opened = checkRiskyPorts(ports)

    # loop over the data 
    for data in results["data"]:
        if "port" in data:
            shodan_score["shodan_score"]["ports"].update({data["port"] : {
                "risky_port" : SHODAN_RISKY_PORT if data["port"] in risky_opened else SHODAN_SAFE_PORT,
                "product" : data["product"] if "product" in data else "N/A",
                "cpe2.3" : data["cpe23"] if "cpe23" in data else "N/A"
            }})

        if "vulns" in data:
        # get the CVEs and CVSS scores for every vulnerability on the service
            for vuln in data["vulns"].keys():     
                shodan_score["shodan_score"]["vulnerabilities"].update({vuln : {"cvss" : data["vulns"][vuln]["cvss"]}})
                cve_count += 1
                cvss_total += float(data["vulns"][vuln]["cvss"])
    
    shodan_score["shodan_score"].update({"last_update" : results["last_update"] if "last_update" in results else "N/A"})
    shodan_score["shodan_score"].update({"OS" : results["os"] if "os" in results else "N/A"})
    shodan_score["shodan_score"].update({"verdict" : calculateResultForEndpoint(cve_count, cvss_total, risky_opened)})

    return shodan_score
    
# compare the open ports of a server against a list
# of known risky ports such as RDP, Telnet, Kerberos etc.
def checkRiskyPorts(port_list):
    tmp = []
    risky = [21, 22, 23, 25, 80, 88, 135, 170, 456, 464, 587, 3389] # subject to change
    for port in port_list:
        if port in risky:
            tmp.append(port)
    return tmp

def calculateResultForEndpoint(cve_count, cvss_total, risky_opened):
    # Formula, as derived on Desmos via trial and error
    # (arctan(cvss_total * cvss_total * cve_count) / cvss_total * cvss_total + 27) / (PI/2)
    # + 27 is an arbitrary offset used to flatten the curve, subject to change
    # get only 1 decimal spot
    return 0.0 if cve_count == 0 else int((atan((cvss_total * cvss_total * cve_count) / (cvss_total * cvss_total + 27) )) / (pi/2) * 1000) / 10