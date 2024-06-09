 
import argparse
import subprocess
import random
import csv
import dns.resolver
import re
import logging
import ipaddress
from functools import lru_cache
import time
import concurrent.futures
from cachetools.func import ttl_cache
import cachetools
import json
from bs4 import BeautifulSoup
from dns.exception import DNSException

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Define DNS servers with weights
DNS_SERVERS = [
    {"address": "8.8.8.8", "weight": 3},
    {"address": "1.1.1.1", "weight": 2},
    {"address": "9.9.9.9", "weight": 1},
    {"address": "64.6.65.6", "weight": 1},
    {"address": "208.67.222.222", "weight": 2}
]

# Create a cache with a maximum size of 1000 entries and a TTL of 1 hour
cache = cachetools.TTLCache(maxsize=1000, ttl=3600)

def is_valid_domain(domain_name):
    pattern = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    )
    return bool(pattern.match(domain_name))

def get_ns_records(domain_name, dns_server_address):
    nslookup_command = f"nslookup -type=ns {domain_name} {dns_server_address}"
    try:
        output = subprocess.check_output(nslookup_command, shell=True).decode("utf-8")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing nslookup: {e} (domain: {domain_name}, DNS server: {dns_server_address})")
        return []
    except Exception as e:
        logger.error(f"Error executing nslookup: {e} (domain: {domain_name}, DNS server: {dns_server_address})")
        return []

    ns_records = []
    for line in output.splitlines():
        if "nameserver" in line:
            ns_record = line.split("=")[1].strip()
            ns_records.append(ns_record)
    return ns_records

@ttl_cache(ttl=3600)   # Cache for 1 hour
def get_ip_address(nameserver, dns_server_address):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server_address]
        answer = resolver.resolve(nameserver, 'A')
        for rdata in answer:
            return rdata.to_text()
    
    except dns.resolver.NoNameservers as e:
        logger.debug(f"No nameservers available for {nameserver} (DNS server: {dns_server_address})")
        return None
    except dns.resolver.Timeout as e:
        logger.warning(f"Timeout while resolving {nameserver} (DNS server: {dns_server_address})")
        return None
    except dns.resolver.NoAnswer as e:
        logger.debug(f"No answer for {nameserver} (DNS server: {dns_server_address})")
        return None
    except dns.resolver.NXDOMAIN as e:
        logger.debug(f"Nameserver {nameserver} does not exist (DNS server: {dns_server_address})")
        return None
    except Exception as e:
        logger.error(f"Error resolving {nameserver}: {e} (DNS server: {dns_server_address})")
        return None

def rotate_dns_server(dns_servers):
    # Weighted round-robin DNS server rotation
    total_weight = sum(server["weight"] for server in dns_servers)
    random_weight = random.randint(0, total_weight - 1)
    for server in dns_servers:
        random_weight -= server["weight"]
        if random_weight <= 0:
            return server["address"]
    return dns_servers[-1]["address"]  # Fallback to last server
# Function to convert ns_record list to a string
def format_ns_record(ns_record):
    # Decode bytes to string and filter out empty strings
    ns_record = [ns.decode('utf-8') for ns in ns_record if ns]
    # Join the parts with '.' to form the FQDN
    return '.'.join(ns_record)

def main():
    parser = argparse.ArgumentParser(description="DNS lookup tools")
    parser.add_argument("domains", nargs="+", help="One or more domain names to lookup")
    parser.add_argument("-d", "--dns-server", help="Custom DNS server address")
    parser.add_argument("-r", "--recursive", action="store_true", help="Perform recursive DNS lookups")
    parser.add_argument("-f", "--format", choices=["csv", "json", "html"], default="csv", help="Output format")
    args = parser.parse_args()
    
    results = []
    for domain in args.domains:
        if not is_valid_domain(domain):
            logger.error(f"Invalid domain name: {domain}. Skipping...")
            continue

        logger.info(f"** Domain: ** {domain}")

        domain_results = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for _ in range(1):  # Perform 3 queries with different DNS servers
                dns_server_address = rotate_dns_server(DNS_SERVERS)
                futures.append(executor.submit(query_dns, domain, dns_server_address, args.recursive))
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    for r in result:
                        domain_results.add(tuple(sorted(r.items())))
                except Exception as e:
                    logger.error(f"Error: {e}")
            results.extend([dict(result) for result in domain_results])  # Convert set back to list of dicts
           
    def format_ns_record(ns_record):
        # Decode bytes to string and filter out empty strings
        ns_record = [ns.decode('utf-8').replace("'", "") for ns in ns_record if ns != "b''"]
        # Join the parts with '.' to form the FQDN
        return '.'.join(ns_record)

    if args.format == "csv":
        with open("results.csv", "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["Domain", "DNS Server", "NS Record", "IP Address"],
                                    dialect='excel',
                                    delimiter=',',
                                    quotechar='"',
                                    quoting=csv.QUOTE_ALL,
                                    lineterminator='\n')
            # Write header row
            writer.writeheader()
            # Write title row
            writer.writerow({"Domain": "# DNS Lookup Results"})
            writer.writerows(results)
        logger.info("** Results saved to results.csv **")
    elif args.format == "json":
        with open("results.json", "w") as jsonfile:
            json_results = []
            for result in results:
                if result is not None:
                    json_result = {
                        "dns_server": str(result["DNS Server"]),
                        "domain": str(result["Domain"]),
                        "ip_address": str(result["IP Address"]),
                        "ns_record": format_ns_record(result["NS Record"])  # Use the function to format ns_record
                    }
                    json_results.append(json_result)
            json.dump(json_results, jsonfile, indent=4, sort_keys=True, separators=(',', ': '))
        logger.info("** Results saved to results.json **")

    elif args.format == "html":
        with open("results.html", "w") as htmlfile:
            html = """
            <html>
              <head>
                <style>
                  table {
                    border-collapse: collapse;
                    width: 100%;
                  }
                  th, td {
                    border: 1px solid #ddd;
                    text-align: left;
                    padding: 8px;
                  }
                  th {
                    background-color: #f0f0f0;
                  }
                </style>
              </head>
              <body>
                <h1>DNS Lookup Results</h1>
                <table>
                  <tr>
                    <th>Domain</th>
                    <th>DNS Server</th>
                    <th>NS Record</th>
                    <th>IP Address</th>
                  </tr>
            """
            for result in results:
                html += "<tr>"
                html += f"<td>{result['Domain']}</td>"
                html += f"<td>{result['DNS Server']}</td>"
                html += f"<td>{result['NS Record']}</td>"
                html += f"<td>{result['IP Address']}</td>"
                html += "</tr>"
            html += """
                </table>
              </body>
            </html>
            """
            soup = BeautifulSoup(html, 'html.parser')
            htmlfile.write(soup.prettify())
        logger.info("** Results saved to results.html **")
@ttl_cache(ttl=3600)  # Cache for 1 hour
def query_dns(domain_name, dns_server_address, recursive_lookups):
    results = set()  # Use a set to keep track of unique results
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server_address]
        answers = resolver.resolve(domain_name, 'NS')
        for rdata in answers:
            ns_record = rdata.target
            ip_address = get_ip_address(ns_record, dns_server_address)
            if ip_address:
                result = tuple(sorted((k, v) for k, v in {
                    "Domain": domain_name,
                    "DNS Server": dns_server_address,
                    "NS Record": ns_record,
                    "IP Address": ip_address
                }.items()))
                results.add(result)  # Add to the set
                if recursive_lookups:
                    recursive_results = query_dns(ns_record, dns_server_address, False)
                    results.update(recursive_results)
    except dns.resolver.NoAnswer as e:
        logger.debug(f"No answer for {domain_name} (DNS server: {dns_server_address})")
    except dns.resolver.NXDOMAIN as e:
        logger.debug(f"Domain {domain_name} does not exist (DNS server: {dns_server_address})")
    except Exception as e:
        logger.error(f"Error resolving {domain_name}: {e} (DNS server: {dns_server_address})")
    return [dict(result) for result in results]  # Convert set back to list of dicts
if __name__ == "__main__":
    start_time = time.time()
    main()
    logger.info(f"** Execution time: ** {time.time() - start_time:.2f} seconds")
    logger.info("** DNS Lookup Tool **")
    logger.info("** Completed Successfully **")