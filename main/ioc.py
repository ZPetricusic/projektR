import ipaddress

with open("data/blacklist.txt") as f: 
    ip_network = ipaddress.ip_network(f.readline().strip())
    print(ipaddress.ip_address("106.11.1.1") in ip_network)
