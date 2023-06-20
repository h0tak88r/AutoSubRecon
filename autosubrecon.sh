#!/bin/bash

# Define directories and files
subs_dir="subs/"
inscope_file="$subs_dir/inscope.txt"
wordlists_dir="Wordlists/"

# Make directories if they don't exist
mkdir -p "$subs_dir"
mkdir -p "$wordlists_dir/dns"

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Passive subdomain enumeration
echo -e "${RED}[+] Let's start with passive subdomain enumeration${NC}"

# Process each domain in inscope.txt
while IFS= read -r domain; do
    # URLs to fetch subdomains from various sources
    urls=(
        "https://rapiddns.io/subdomain/$domain?full=1#result"
        "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey"
        "https://crt.sh/?q=%.$domain"
        "https://crt.sh/?q=%.%.$domain"
        "https://crt.sh/?q=%.%.%.$domain"
        "https://crt.sh/?q=%.%.%.%.$domain"
        "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns"
        "https://api.hackertarget.com/hostsearch/?q=$domain"
        "https://urlscan.io/api/v1/search/?q=$domain"
        "https://jldc.me/anubis/subdomains/$domain"
        "https://www.google.com/search?q=site%3A$domain&num=100"
        "https://www.bing.com/search?q=site%3A$domain&count=50"
    )

    # Fetch subdomains from various sources concurrently
    echo -e "${YELLOW}[+] Getting $domain subdomains using [crt.sh+rapiddns+alienvault+hackertarget+urlscan+jldc+google+bing]${NC}"

    for url in "${urls[@]}"; do
        curl -s "$url" | grep -o -E '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.'"$domain"'' >> "$subs_dir/passive.txt" &
    done

    wait

    echo -e "${BLUE}[+] Removing duplicates from passive subdomains${NC}"
    cat "$subs_dir/passive.txt" | sort -u > "$subs_dir/quick_passive.txt"
    rm "$subs_dir/passive.txt"

    echo -e "${BLUE}[+] Saving to quick_passive.txt${NC}"
    echo "$domain" >> "$subs_dir/quick_passive.txt"

    echo -e "${BLUE}[+] That's it, we are done for $domain!${NC}"
done < "$inscope_file"

# Subfinder to fetch subdomains
echo -e "${BLUE}[+] Running subfinder to fetch subdomains${NC}"
subfinder -dL "$inscope_file" -o "$subs_dir/subfinder.txt" -all

# Done with passive subdomain enumeration
echo -e "${RED}[+] Done with Passive subdomain enumeration!${NC}"

# Active subdomain enumeration
echo -e "${RED}[+] Start active subdomain enumeration!${NC}"

# 1. DNS Brute Forcing using puredns
echo -e "${GREEN}[+] DNS Brute Forcing using puredns${NC}"
puredns bruteforce "$wordlists_dir/dns/dns_9m.txt" "$domain" -r "$wordlists_dir/dns/valid_resolvers.txt" -w "$subs_dir/dns_bf.txt"

# 2. Permutations using gotator
echo -e "${GREEN}[+] Permutations using gotator${NC}"
gotator -sub "$inscope_file" -perm "$wordlists_dir/dns/dns_permutations_list.txt" -depth 1 -numbers 10 -mindup -adv -md | sort -u > "$subs_dir/perms.txt"

# Resolving permutations using puredns
echo -e "${GREEN}[+] Resolving permutations using puredns${NC}"
puredns resolve "$subs_dir/perms.txt" -r "$wordlists_dir/dns/valid_resolvers.txt" -w "$subs_dir/resolved_perms.txt"

# 3. TLS probing using cero
echo -e "${GREEN}[+] TLS probing using cero${NC}"
while IFS= read -r domain; do
    cero "$domain" | sed 's/^*.//' | grep -e "\." | sort -u
done < "$inscope_file" | tee -a "$subs_dir/tls_probing.txt"

# 4. Scraping (JS/Source code)
echo -e "${GREEN}[+] Scraping (JS/Source code)${NC}"
cat "$subs_dir/"* | sort -u > "$subs_dir/filtered_subs.txt"
cat "$subs_dir/filtered_subs.txt" | httpx -random-agent -retries 2 -o "$subs_dir/filtered_hosts.txt"

# Crawling using gospider
echo -e "${GREEN}[+] Crawling for js files using gospider${NC}"
gospider -S "$subs_dir/filtered_hosts.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "$subs_dir/gospider.txt"

# Cleaning the output
echo -e "${GREEN}[+] Cleaning the output${NC}"
sed -i '/^.\{2048\}./d' "$subs_dir/gospider.txt"
cat "$subs_dir/gospider.txt" | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep -Eo '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.[^.]{2,}' | sort -u > "$subs_dir/scrap_subs.txt"

# Resolving target subdomains
echo -e "${GREEN}[+] Resolving target subdomains${NC}"
puredns resolve "$subs_dir/scrap_subs.txt" -r "$wordlists_dir/dns/valid_resolvers.txt" -w "$subs_dir/scrap_subs_resolved.txt"

# Done with active subdomain enumeration
echo -e "${RED}[+] Done with Active subdomain enumeration!${NC}"

# Finishing our subdomain enumeration
echo -e "${BLUE}[+] Finishing our work and filtering out the subdomains${NC}"
cat "$subs_dir/"* | sort -u > "$subs_dir/filtered_subs.txt"
cat "$subs_dir/filtered_subs.txt" | httpx -random-agent -retries 2 -o "$subs_dir/filtered_hosts.txt"
cat "$subs_dir/filtered_hosts.txt" | sort -u > "$subs_dir/filtered_hosts.txt"
echo -e "${RED}[+] That's it, we are done with subdomain enumeration!${NC}"
