import sys
import validators
import socket
from pathlib import Path
from urllib.parse import urlparse


def printBanner(s):
    banner = f"*    {s}    *"
    # empty newline
    print()
    print("*" * len(banner))
    print(banner)
    print("*" * len(banner))
    # empty newline
    print()

def loadFiles():
    # Read in the crawler file
    try:
        data_file_path = sys.argv[1]
    except:
        print("[!] Error: No crawler URLs provided", file=sys.stderr)
        print("[!] Usage: python main.py <crawler data path> <blacklist data path>", file=sys.stderr)
        sys.exit(1)

    # read in the IP blacklist file
    try:
        blacklist_file_path = sys.argv[2]
    except:
        print("[!] Error: No blacklist file provided", file=sys.stderr)
        print("[!] Usage: python main.py <crawler data path> <blacklist data path>", file=sys.stderr)
        sys.exit(1)

    # only allow .csv or .txt files
    allowed_formats = ("csv", "txt")

    if not (data_file_path.endswith(allowed_formats) and blacklist_file_path.endswith(allowed_formats)):
        print(
            "[!] Error: The provided files have to be in .txt or .csv format!",
            file=sys.stderr,
        )
        print("[!] Usage: python main.py <crawler data path> <blacklist data path>", file=sys.stderr)
        sys.exit(1)

    # check if the files exist
    data_file = Path(data_file_path)
    blacklist_file = Path(blacklist_file_path)

    if not data_file.is_file():
        print(
            f"[!] Error: The provided file could not be found: {data_file_path}",
            file=sys.stderr,
        )
        print("[!] Usage: python main.py <crawler data path> <blacklist data path>", file=sys.stderr)
        sys.exit(1)
    
    if not blacklist_file.is_file():
        print(
            f"[!] Error: The provided file could not be found: {blacklist_file_path}",
            file=sys.stderr,
        )
        print("[!] Usage: python main.py <crawler data path> <blacklist data path>", file=sys.stderr)
        sys.exit(1)
    
    return data_file, blacklist_file

def buildEndpoint(url):
    if not "//" in url: # netloc is empty if no // is in the url..
        url = "//" + url
    parsed_url = urlparse(url)
    return f"{parsed_url.path}{f'?{parsed_url.query}' if len(parsed_url.query) > 0 else ''}"


def buildFinalJSON(data_file):
    endpoint_counter = 0
    domain_counter = 0

    # list of urls in order to remove invalid URLs
    url_list = list()

    # domain dict in order to shorten the IP retrieval time
    # and speed up the formatting process
    domain_dict = {} 
    with open(data_file) as urls:
        for url in urls:
            # remove the newline at the end
            url = url.strip()
            # skip any possible lines which are not URL strings
            if validators.url(url):
                # parse the URL for end-result formatting
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                endpoint = buildEndpoint(url)

                # if we have already registered the domain skip this step
                if domain not in domain_dict.keys():
                    # create the *domain* key which we will add into the results later
                    domain_dict.update({domain : {"ip_data" : [], "endpoint_data" : []}})
                    domain_counter += 1
                    try:
                        # set of domains used for IP analysis
                        ip_set = set()
                        for ip in socket.getaddrinfo(domain, 0): # 0 for all services
                            # 4 is the index of the (IP, port) tuple
                            # 0 is the index of the IP in the tuple
                            ip_set.add(ip[4][0]) 

                        # since dict is unhashable we cannot do
                        # ip_set.add({ip[4][0] : {}})
                        for ip in ip_set:
                        # fill the specified domain with the IP details
                            domain_dict[domain]["ip_data"].append({ip : {"scores" : {}}}) 

                    except:
                        print(f"Could not resolve IP addresses for domain '{domain}', continuing..")
                        try:
                            # since we have already added the key
                            # remove it to prevent unnecessary API calls
                            del domain_dict[domain]
                            domain_counter -= 1
                        except:
                            print(f"[!] Errored while trying to remove domain '{domain}' from the formatted list, continuing")
                        continue
                    
                # fill the specified domain with the endpoint details
                domain_dict[domain]["endpoint_data"].append({endpoint : {"scores" : {}}})
                endpoint_counter += 1
            else:
                print(f"[-] Skipping URL '{url}'")

        print("\n[✓] Successfully filtered URLs")
        print(f"[✓] The list now contains {endpoint_counter} endpoints and {domain_counter} domains")

        return domain_dict

