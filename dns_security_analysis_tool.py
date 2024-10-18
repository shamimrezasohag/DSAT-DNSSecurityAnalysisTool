import time
import sys
import os
import dns.resolver
import dns.reversename
import dns.query
import dns.message
import dns.rdatatype
import dns.dnssec
import argparse
import logging
import pandas as pd
import subprocess
import re
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# # Setup logging for recording the process and errors
logging.basicConfig(filename='dns_security_audit.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

class DNSQueryTool:
    def __init__(self, dns_server):
        # Initialize the resolver with the specified DNS server
        self.resolver = dns.resolver.Resolver()
#        self.resolver.nameservers = [dns_server]
        self.default_nameserver = dns_server


    def query_all_records(self, domain):
        # Query multiple DNS record types for a given domain
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SPF', 'DKIM', 'DNSKEY', 'DS']
        results = {'domain': domain}
        for record_type in record_types[:2]:
            results[record_type]= self.query_record(domain, record_type)
        print(results)
        if results['A'] == results['AAAA'] == 'DNE':
            return {'domain': domain, 'Error': 'Domain does not exist'}
        for record_type in record_types[2:]:
            results[record_type]= self.query_record(domain, record_type)
        results['PTR'] = self.check_reverse_dns(results.get('A', '') + results.get('AAAA', ''))
        results['Open Resolver'] = self.check_open_resolver(domain)
        results['DNSSEC'] = self.check_dnssec(domain, results.get('NS', ''))
        results['Anomalies'] = self.analyze_records(results)
        # Empty and unnecessary data filtering
        results = {k: v for k, v in results.items() if v and v != ''}
        return results

    def query_record(self, domain, record_type, nameserver=None):
        # Perform a DNS query for a specific record type using the specified nameserver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver] if nameserver else [self.default_nameserver]
        try:
            answers = resolver.resolve(domain, record_type)
            return "; ".join([answer.to_text() for answer in answers])
        except dns.resolver.NXDOMAIN:
            if record_type == 'A' or record_type == 'AAAA':
                try:
                    resolver.resolve(domain, 'CNAME')
                    return f"Misconfigured"
                except:
                    return f"DNE"  # Does Not Exist
        except Exception as e:
            logging.error(f"Error querying {record_type} record for {domain}: {e}")
            return ""
    def check_reverse_dns(self, ip_addresses):
        # Perform reverse DNS lookups for given IP addresses/got from the A record
        ptr_records = []
        for ip in ip_addresses.split("; "):
            try:
                reversed_ip = dns.reversename.from_address(ip)
                ptr_record = self.resolver.resolve(reversed_ip, "PTR")
                ptr_records.extend([record.to_text() for record in ptr_record])
            except Exception as e:
                ptr_records.append(str(e))
        return "; ".join(ptr_records)
    
    # Revised the logic to check the open_dns_resolver, Check if a DNS server is an open resolver using the 'dig' command
    def check_open_resolver(self, domain):
        try:
            result = subprocess.run(
                ["dig", "+short", "test.openresolver.com", "TXT", f"@{domain}"],
                capture_output=True,
                text=True
            )
            return "Open Resolver" if "ANSWER" in result.stdout else ""
        except subprocess.CalledProcessError:
            return "Check Failed"

    def check_dnssec(self, domain, nameservers):
        # Validate the DNSSEC records for a given domain
        if nameservers:
            request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
            nameservers = nameservers.split("; ")
            for nameserver in nameservers:
                try:
                    nsresponse = self.resolver.resolve(nameserver,dns.rdatatype.A)
                    nsaddr = nsresponse.rrset[0].to_text()
                    response = dns.query.tcp(request, nsaddr) # udp returns truncated answers
                    if response.rcode() != 0:
                        continue
                    answer = response.answer
                    if len(answer) != 2:
                        continue
                except Exception:
                    continue

                try:
                    # Validate DNSSEC signatures
                    name = dns.name.from_text(domain)
                    dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
                    return "DNSSEC Verified"
                except Exception as e:
                    return f"DNSSEC Not Verified: {e}"

        return "DNSSEC Not Verified: missing DNSKEY"

    def analyze_records(self, records):
        anomalies = {}
        # Insert anomaly detection logic here
        # Example: Check for unusual MX records
        mx_records = records.get('MX', "")
        if mx_records is not None and 'suspicious' in mx_records.lower():
            anomalies['MX'] = "Suspicious MX record found"
        # Additional anomaly checks can be added here
        return "; ".join([f"{k}: {v}" for k, v in anomalies.items()])
        # New Method: Query DNS from Multiple Regions
    def query_from_multiple_regions(self, domain, record_type="A"):
        dns_servers = {
            "Google DNS (US)": "8.8.8.8",
            "Cloudflare DNS (Global)": "1.1.1.1",
            "Quad9 DNS (EU)": "9.9.9.9",
            "OpenDNS (US)": "208.67.222.222"
        }
        results = {}
        for location, nameserver in dns_servers.items():
            result = self.query_record(domain, record_type, nameserver)
            results[location] = result
        return results

    # New Method: Check DNSSEC from Multiple Regions
    def check_dnssec_global(self, domain):
        # Check DNSSEC status from different geographic locations
        dns_servers = {
            "Google DNS (US)": "8.8.8.8",
            "Cloudflare DNS (Global)": "1.1.1.1",
            "Quad9 DNS (EU)": "9.9.9.9",
            "OpenDNS (US)": "208.67.222.222"
        }
        dnssec_results = {}
        for location, nameserver in dns_servers.items():
            self.resolver.nameservers = [nameserver]
            dnssec_status = self.check_dnssec(domain, '')
            dnssec_results[location] = dnssec_status
        return dnssec_results

    # New Method: Measure DNS Query Latency
    def latency_check(self, domain):
        dns_servers = {
            "Google DNS (US)": "8.8.8.8",
            "Cloudflare DNS (Global)": "1.1.1.1",
            "Quad9 DNS (EU)": "9.9.9.9",
            "OpenDNS (US)": "208.67.222.222"
        }
        latencies = {}
        for location, nameserver in dns_servers.items():
            start_time = time.time()
            self.query_record(domain, "A", nameserver)
            latency = time.time() - start_time
            latencies[location] = latency
        return latencies

def generate_report(all_data, output_format, output_filename):
    # Create a DataFrame from the cleaned and processed data
    df = pd.DataFrame(all_data)

    # Enhanced report formatting
    # Ensuring that missing fields are clearly marked as 'Not Available'
    df.fillna("Not Available", inplace=True)

    # Renaming columns for better readability (optional, depending on need)
    df.rename(columns={
        'A': 'A Record',
        'AAAA': 'AAAA Record',
        'MX': 'MX Record',
        'PTR': 'PTR Record',
        'DNSSEC': 'DNSSEC Status',
        'Global DNS Results': 'Global DNS Records',
        'Latencies': 'DNS Latency',
        'DNSSEC Global': 'DNSSEC Global Status'
    }, inplace=True)

    # Generate a report in the specified format (CSV, HTML, JSON)
    if output_format == 'csv':
        df.to_csv(output_filename, index=False)
    elif output_format == 'html':
        df.to_html(output_filename, index=False)
    else:
        with open(output_filename, 'w') as file:
            file.write(json.dumps(all_data, indent=4))

def enhance_report(df):
    # Initialize a list to store enhanced rows
    enhanced_rows = []

    # Iterate over each row to break down the Global DNS Results and Latencies
    for _, row in df.iterrows():
        # Ensure the data is in string format before using eval (check if eval is necessary)
        global_dns = row.get('Global DNS Results', {})
        latencies = row.get('Latencies', {})
        dnssec_global = row.get('DNSSEC Global', {})

        # Convert to dictionaries if they are in string format (using eval cautiously)
        try:
            if isinstance(global_dns, str):
                global_dns = eval(global_dns)
            if isinstance(latencies, str):
                latencies = eval(latencies)
            if isinstance(dnssec_global, str):
                dnssec_global = eval(dnssec_global)
        except Exception as e:
            logging.error(f"Error processing row: {e}")
            continue

        # Create a new row with the necessary enhancements
        enhanced_row = {
            'Domain': row.get('domain', 'Unknown Domain'),
            'A Record': row.get('A', 'Not Available'),
            'AAAA Record': row.get('AAAA', 'Not Available'),
            'MX Record': row.get('MX', 'Not Available'),
            'PTR Record': row.get('PTR', 'Not Available'),
            'DNSSEC Status': row.get('DNSSEC', 'Not Available'),
        }

        # Add global DNS results and latencies for each DNS provider
        for provider in ['Google DNS (US)', 'Cloudflare DNS (Global)', 'Quad9 DNS (EU)', 'OpenDNS (US)']:
            enhanced_row[f'{provider} A Record'] = global_dns.get(provider, 'Not Available')
            enhanced_row[f'{provider} Latency'] = f"{latencies.get(provider, 'N/A')} seconds"
            enhanced_row[f'{provider} DNSSEC'] = dnssec_global.get(provider, 'Not Verified')

        # Append the enhanced row to the list
        enhanced_rows.append(enhanced_row)

    # Create a new DataFrame from the enhanced rows
    enhanced_df = pd.DataFrame(enhanced_rows)
    return enhanced_df


def process_domains(domains, dns_server, output_format, output_filename, global_analysis=False):
    pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
    valid_domains = [domain for domain in domains if re.match(pattern, domain) is not None and domain.strip()]
    
    # Initialize the tool with the specified DNS server
    tool = DNSQueryTool(dns_server)
    all_results = []
    max_threads = 10  # You can adjust the number of threads

    skipped_domains_count = len(domains) - len(valid_domains)

    with tqdm(total=len(valid_domains), desc="Analyzing Domains") as pbar:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(tool.query_all_records, domain): domain for domain in valid_domains}

            for future in as_completed(futures):
                dns_results = future.result()

                # Run global analysis if the flag is set
                if global_analysis:
                    global_dns_results = tool.query_from_multiple_regions(dns_results['domain'])
                    latencies = tool.latency_check(dns_results['domain'])
                    dnssec_global_results = tool.check_dnssec_global(dns_results['domain'])

                    dns_results['Global DNS Results'] = global_dns_results
                    dns_results['Latencies'] = latencies
                    dns_results['DNSSEC Global'] = dnssec_global_results

                all_results.append(dns_results)
                pbar.update(1)

    if skipped_domains_count > 0:
        logging.warning(f"Skipped {skipped_domains_count} invalid domain rows")

    # Convert the results to a DataFrame
    df = pd.DataFrame(all_results)

    # Enhance the report before generating the final output
    enhanced_df = enhance_report(df)

    # Generate the final output
    generate_report(enhanced_df, output_format, output_filename)


def main():
    parser = argparse.ArgumentParser(description='Comprehensive DNS Security Analysis Tool')
    parser.add_argument('--domains-file', required=True, help='Input file for bulk domain security analysis')
    parser.add_argument('--dns-server', default='8.8.8.8', help='DNS server to use for queries')
    parser.add_argument('--format', default='json', choices=['json', 'csv', 'html'], help='Format of the security report')
    parser.add_argument('--output', '-o', default='dns_security_report', help='Output file name for the DNS security report')
    parser.add_argument('--global-analysis', action='store_true', help='Enable global CDN and Anycast DNS analysis')
    args = parser.parse_args()

    with open(args.domains_file, 'r') as file:
        domains = [line.strip() for line in file]

    output_filename = f"{args.output}.{args.format}"
    process_domains(domains, args.dns_server, args.format, output_filename, global_analysis=args.global_analysis)

if __name__ == "__main__":
    main()

