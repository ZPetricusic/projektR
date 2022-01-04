import sys
import validators
import asyncio
from gsb import *
from auxiliaries import *
from urllib.parse import urlparse

async def main():

    # Read in the crawler file
    try:
        data_file = sys.argv[1]
    except:
        print("[!] Error: No crawler URLs provided", file=sys.stderr)
        print("[!] Usage: python main.py <crawler filename>", file=sys.stderr)
        sys.exit(1)

    # only allow .csv or .txt files
    allowed_formats = ("csv", "txt")

    if not data_file.endswith(allowed_formats):
        print("[!] Error: The provided URL file has to be in .txt or .csv format!", file=sys.stderr)
        print("[!] Usage: python main.py <crawler filename>", file=sys.stderr)
        sys.exit(1)

    # set of urls in order to remove all duplicates
    url_set = set()

    # starting stage 1
    printBanner("STAGE 1 - REMOVING DUPLICATE URLS FROM CRAWLER DATA")

    try:
        with open(data_file) as urls:
            for url in urls:
                # remove the newline at the end
                url = url.strip()
                # skip any possible lines which are not URL strings
                if validators.url(url):
                    url_set.add(url)
                else:
                    print(f"[-] Skipping URL {url}")

            print("\n[✓] Successfully filtered URLs")
            print(f"[✓] The set now contains {len(url_set)} domains")

    except Exception as e:
        print(e)
        sys.exit(1)

    # starting stage 2
    printBanner("STAGE 2 - ANALYZING URL SET")

    # chunkify the URL set into lists of gsb.CHUNKS
    # converting to list since set is not subscriptable
    # source: https://stackoverflow.com/questions/434287/what-is-the-most-pythonic-way-to-iterate-over-a-list-in-chunks
    url_chunks = (list(url_set)[pos:pos + CHUNKS] for pos in range(0, len(url_set), CHUNKS))

    # final results will be displayed as a dictionary:
    # {url : {gsb_score: x, vt_score..., total_score: formula}, ..}

    final_scores = {}

    # after filtering the crawler data use the in-memory set to run the tests

    # start with GSB checks
    for url_chunk in url_chunks:
        data = createGSBRequestFromTemplate(url_chunk)
        await GSBanalyse(data, final_scores)
        
    print(final_scores)
        


if __name__ == '__main__':
   asyncio.run(main()) 

