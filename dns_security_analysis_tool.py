import dns.resolver
import dns.reversename
import argparse
import logging
import pandas as pd

# Setup logging
logging.basicConfig(filename='dns_security_audit.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

class DNSQueryTool:
    def __init__(self, dns_server):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [dns_server]

    def query_all_records(self, domain):
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SPF', 'DKIM', 'DNSKEY', 'DS']
        results = {'domain': domain}
        for record_type in record_types:
            results[record_type], results[f'{record_type}_response_code'] = self.query_record(domain, record_type)
        results['PTR'], _ = self.check_reverse_dns(results.get('A', "") + results.get('AAAA', ""))
        results['Open Resolver'] = self.check_open_resolver(domain)
        results['DNSSEC'] = self.check_dnssec(domain)
        results['Anomalies'] = self.analyze_records(domain, results)
        return results

    def query_record(self, domain, record_type):
        try:
            answers = self.resolver.resolve(domain, record_type)
            return "; ".join([answer.to_text() for answer in answers]), "NOERROR"
        except dns.resolver.NoAnswer:
            return "", "NOANSWER"
        except dns.resolver.NXDOMAIN:
            return "", "NXDOMAIN"
        except dns.resolver.Timeout:
            return "", "TIMEOUT"
        except Exception as e:
            return "", str(e)

    def check_reverse_dns(self, ip_addresses):
        ptr_records = []
        for ip in ip_addresses.split("; "):
            try:
                reversed_ip = dns.reversename.from_address(ip)
                ptr_record = self.resolver.resolve(reversed_ip, "PTR")
                ptr_records.extend([record.to_text() for record in ptr_record])
            except Exception as e:
                ptr_records.append(str(e))
        return "; ".join(ptr_records), "NOERROR"

    def check_open_resolver(self, domain):
        try:
            self.resolver.resolve('example.com', 'A')
            return "Potentially Open Resolver"
        except Exception:
            return "Not an Open Resolver"

    def check_dnssec(self, domain):
        try:
            self.resolver.resolve(domain, 'A', want_dnssec=True)
            return "DNSSEC Verified"
        except Exception as e:
            return f"DNSSEC Not Verified: {e}"

    def analyze_records(self, domain, records):
        anomalies = {}
        mx_records = records.get('MX', "")
        if 'suspicious' in mx_records:
            anomalies['MX'] = "Suspicious MX record found"
        # Additional analyses as needed
        return "; ".join([f"{k}: {v}" for k, v in anomalies.items()])

def generate_report(all_data, output_format, output_filename):
    df = pd.DataFrame(all_data)
    if output_format == 'csv':
        df.to_csv(output_filename, index=False)
    elif output_format == 'html':
        df.to_html(output_filename, index=False)
    else:
        df.to_json(output_filename, orient='records', indent=4)

def process_domains(domains, dns_server, output_format, output_filename):
    tool = DNSQueryTool(dns_server)
    all_results = []

    for domain in domains:
        dns_results = tool.query_all_records(domain)
        all_results.append(dns_results)

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
