import ipaddress

IOC_SCORE_POSITIVE = 'MALICIOUS'
IOC_SCORE_NEGATIVE = 'SAFE'

def IOCanalyse(ip_data_list, blacklist_file):
    IOC_malicious_IPs = []
    # the loaded IP blacklist file
    with open(blacklist_file) as f: 
        for ip in ip_data_list:
            for ioc in f:
                ioc = ioc.strip()
                # if we're not looking at a subnet
                try:
                    if not "/" in ioc:
                        if ip == ioc:
                            IOC_malicious_IPs.append(ip)
                    else:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(ioc):
                            IOC_malicious_IPs.append(ip)
                except Exception as e:
                    print(e)
    return IOC_malicious_IPs