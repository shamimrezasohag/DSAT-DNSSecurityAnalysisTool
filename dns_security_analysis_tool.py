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
import requests
import re
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# # Setup logging for recording the process and errors
logging.basicConfig(filename='dns_security_audit.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

class DNSQueryTool:
    def __init__(self, dns_server):
        # Initialize the resolver with the specified DNS server
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [dns_server]

    def query_all_records(self, domain):
        # Query multiple DNS record types for a given domain
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SPF', 'DKIM', 'DNSKEY', 'DS']
        results = {'domain': domain}
        for record_type in record_types:
            record, response_code = self.query_record(domain, record_type)
            if response_code == "NXDOMAIN":
                results['Error'] = 'Domain does not exist'
                break  # Skip remaining checks as domain doesn't exist
            if record:
                results[record_type] = record
                results[f'{record_type}_response_code'] = response_code

        for record_type in record_types:
            results[record_type], results[f'{record_type}_response_code'] = self.query_record(domain, record_type)
        results['PTR'], _ = self.check_reverse_dns(results.get('A', '') + results.get('AAAA', ''))
        results['Open Resolver'] = self.check_open_resolver(domain)
        results['DNSSEC'] = self.check_dnssec(domain, results.get('NS', ''))
        results['Anomalies'] = self.analyze_records(results)
        return results
        for record_type in record_types:
            record, response_code = self.query_record(domain, record_type)
            if record:  # Only add non-empty records
                results[record_type] = record
                results[f'{record_type}_response_code'] = response_code

    def query_record(self, domain, record_type):
        # Perform a DNS query for a specific record type
        try:
            answers = self.resolver.resolve(domain, record_type)
            return "; ".join([answer.to_text() for answer in answers]), "NOERROR"
        except dns.resolver.NXDOMAIN:
            return "Domain does not exist", "NXDOMAIN"
        except Exception as e:
            return "", str(e)

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
        return "; ".join(ptr_records), "NOERROR"
    
    # Revised the logic to check the open_dns_resolver, Check if a DNS server is an open resolver using the 'dig' command
    def check_open_resolver(self, domain):
        try:
            result = subprocess.run(
                ["dig", "+short", "test.openresolver.com", "TXT", f"@{domain}"],
                capture_output=True,
                text=True
            )
            return "Open Resolver" if "ANSWER" in result.stdout else "Not an Open Resolver"
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
        if 'suspicious' in mx_records:
            anomalies['MX'] = "Suspicious MX record found"
        # Additional anomaly checks can be added here
        return "; ".join([f"{k}: {v}" for k, v in anomalies.items()])

def generate_report(all_data, output_format, output_filename):
    # Generate a report in the specified format (CSV, HTML, JSON)
    df = pd.DataFrame(all_data)
    if output_format == 'csv':
        df.to_csv(output_filename, index=False)
    elif output_format == 'html':
        df.to_html(output_filename, index=False)
    else:
        df.to_json(output_filename, orient='records', indent=4)

def process_domains(domains, dns_server, output_format, output_filename):

    def is_valid_domain(domain):
        pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
        return re.match(pattern, domain) is not None

    # ... inside your process_domains function ...
    valid_domains = [domain for domain in domains if is_valid_domain(domain)]

    # Process a list of domains for DNS security analysis
    tool = DNSQueryTool(dns_server)
    all_results = []
    max_threads = 10  # You can adjust the number of threads

     # Filter out empty domains and prepare for progress tracking
    filtered_domains = [domain for domain in domains if domain.strip()]
    skipped_domains_count = len(domains) - len(filtered_domains)

    with tqdm(total=len(filtered_domains), desc="Analyzing Domains") as pbar:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Create a future for each domain in the filtered list
            futures = {executor.submit(tool.query_all_records, domain): domain for domain in filtered_domains}

            for future in as_completed(futures):
                dns_results = future.result()
                all_results.append(dns_results)
                pbar.update(1)

    if skipped_domains_count > 0:
        logging.warning(f"Skipped {skipped_domains_count} empty domain rows")

    generate_report(all_results, output_format, output_filename)

def main():
    parser = argparse.ArgumentParser(description='Comprehensive DNS Security Analysis Tool')
    parser.add_argument('--domains-file', required=True, help='Input file for bulk domain security analysis')
    parser.add_argument('--dns-server', default='8.8.8.8', help='DNS server to use for queries')
    parser.add_argument('--format', default='json', choices=['json', 'csv', 'html'], help='Format of the security report')
    parser.add_argument('--output', default='dns_security_report', help='Output file name for the DNS security report')
    args = parser.parse_args()

    with open(args.domains_file, 'r') as file:
        domains = [line.strip() for line in file]

    output_filename = f"{args.output}.{args.format}"
    process_domains(domains, args.dns_server, args.format, output_filename)

if __name__ == "__main__":
    main()
