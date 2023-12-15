# DSAT-DNSSecurityAnalysisTool

## Description
The DNS Security Analysis Tool is a Python-based utility designed to conduct an in-depth security analysis of DNS configurations for multiple domains. It queries a wide range of DNS record types and performs specialized checks, including DNSSEC verification, open resolver detection, and reverse DNS mismatch analysis. This tool is particularly useful for network administrators, cybersecurity professionals, and anyone interested in DNS security.

## Key Features
- **Comprehensive DNS Record Queries**: Retrieves various DNS record types such as A, AAAA, MX, TXT, NS, CNAME, SOA, SPF, DKIM, DNSKEY, DS.
- **DNSSEC Verification**: Checks for the implementation of DNSSEC, enhancing the security of DNS queries.
- **Open Resolver Detection**: Identifies potential open resolvers that might be used in DNS amplification attacks.
- **Reverse DNS Mismatch Analysis**: Examines mismatches between forward and reverse DNS records.
- **Anomaly Detection**: Basic analysis to identify potential anomalies and unusual entries in DNS records.
- **Response Code Logging**: Captures and logs DNS response codes for each query for further analysis.

## Prerequisites
- Python 3.x
- `dnspython` library

## Installation
1. Clone the repository:
`git clone <repository-url>`
2. Navigate to the cloned directory:
`cd dns-security-analysis-tool`
3. Install the required Python package:
`pip install dnspython`
`pip install pandas`

## Usage
Run the script from the command line by specifying the input file containing domain names and other optional parameters:
`python3 dns_security_analysis_tool.py --domains-file domains.txt --format csv --output dns_security_report`

### Command-Line Arguments
- `--domains-file`: Path to the file containing the list of domains for analysis.
- `--dns-server`: (Optional) DNS server to use for queries (default: 8.8.8.8).
- `--format`: (Optional) output report format (`json`, `csv`, `html`).
- `--output`: (Optional) Name of the output file (without extension).

## Contributing
I want you to know that contributions to this project are welcome. Please feel free to fork the repository, make your changes, and submit a pull request.

## License
This project is licensed under the Apache License 2.0. Please take a look at the [LICENSE](LICENSE) file for more details.

## Contact
For any questions or feedback, please contact [Shamim](mailto:shamimreza@sohag.shamim@gmail.com).


