# AutoSubRecon

AutoSubRecon is a bash script designed to automate the subdomain enumeration process, providing both passive and active enumeration options. It leverages various tools to gather subdomains and filter out the results for further analysis.
# Usage
- `bash autosubrecon.sh <target>`

## Workflow

### Passive Subdomain Enumeration

1. **Passive Gathering**: AutoSubRecon retrieves subdomains using multiple sources, including crt.sh, RapidDNS, AlienVault, HackerTarget, URLScan, Jldc, Google, and Bing.
2. **Subfinder**: The script runs the [subfinder](https://github.com/projectdiscovery/subfinder) tool to fetch additional subdomains.

### Active Subdomain Enumeration

1. **DNS Brute Forcing**: AutoSubRecon utilizes [puredns](https://github.com/d3mondev/puredns) to perform DNS brute-forcing for subdomain discovery.
2. **Permutations**: The tool generates permutations using [gotator](https://github.com/Josue87/gotator) to uncover potential subdomains.
3. **Resolving Permutations**: AutoSubRecon resolves the generated permutations using puredns.
4. **SSL/TLS Probing**: The script employs [cero](https://github.com/glebarez/cero) for SSL/TLS probing to discover subdomains.

### JS Scraping (Optional)

1. **Crawling**: AutoSubRecon utilizes [gospider](https://github.com/jaeles-project/gospider) to crawl JavaScript files and extract potential subdomains.
2. **Output Cleaning**: The script cleans the output and fetches domains using [unfurl](https://github.com/tomnomnom/unfurl).
3. **Resolving Output Subdomains**: AutoSubRecon resolves the obtained subdomains using puredns.

### Finishing Work

1. **Subdomain Filtering**: AutoSubRecon removes duplicate subdomains and saves the filtered results in **filtered_subs.txt**.
2. **Host Discovery**: The script utilizes [httpx](https://github.com/encode/httpx) to fetch corresponding hosts for the filtered subdomains, saving the results in **filtered_hosts.txt**.

## Requirements

To run AutoSubRecon, follow these steps:

1. Install the required tools mentioned above.
2. Clone the [Wordlists](https://github.com/h0tak88r/Wordlists) repository.
3. Create a file named **inscope.txt** in the **subs/** directory and add your target domains.

By following these instructions, you can automate the subdomain enumeration process using AutoSubRecon and efficiently discover potential subdomains for your target domains.
