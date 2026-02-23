#!/bin/bash

# Set the target domain
target_domain="$1"

# Check if target_domain is provided
if [ -z "$target_domain" ]; then
  echo "[+] Usage: $0 domain.com"
  exit 1
fi

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ascii_art=''' 
┏┓┳┳┏┳┓┏┓┏┓┳┳┳┓┳┓┏┓┏┓┏┓┳┓
┣┫┃┃ ┃ ┃┃┗┓┃┃┣┫┣┫┣ ┃ ┃┃┃┃
┛┗┗┛ ┻ ┗┛┗┛┗┛┻┛┛┗┗┛┗┛┗┛┛┗ by @h0tak88r
'''
echo -e "${RED} $ascii_art ${NC}"

# Ensure we are in the script directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Required Wordlists
DNS_2M="Wordlists/dns/dns_2m.txt"
RESOLVERS="Wordlists/dns/valid_resolvers.txt"
PERM_LIST="Wordlists/dns/dns_permutations_list.txt"

check_tools() {
    local tools=("subfinder" "puredns" "gotator" "cero" "httpx" "gospider" "unfurl" "curl" "grep" "sort" "sed")
    local missing_tools=()
    
    echo "[+] Checking for required tools..."
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}[!] Please install the missing tools before running the script${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] All required tools are installed!${NC}"
}

setup_dir() {
    echo "[+] Setting up work directory..."
    rm -rf subs
    mkdir -p subs
}

passive_recon() {
    echo "[+] Starting passive subdomain enumeration..."
    
    # Background various passive sources
    echo "[+] Fetching from multiple sources (parallel)..."
    (curl -s "https://rapiddns.io/subdomain/$target_domain?full=1#result" | grep -oE "[a-zA-Z0-9._-]+\.$target_domain" >> "subs/passive_raw.txt") &
    (curl -s "http://web.archive.org/cdx/search/cdx?url=*.$target_domain/*&output=text&fl=original&collapse=urlkey" | grep -oE "[a-zA-Z0-9._-]+\.$target_domain" >> "subs/passive_raw.txt") &
    (curl -s "https://crt.sh/?q=%.$target_domain" | grep -oE "[a-zA-Z0-9._-]+\.$target_domain" >> "subs/passive_raw.txt") &
    (curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$target_domain/passive_dns" | grep -oE "[a-zA-Z0-9._-]+\.$target_domain" >> "subs/passive_raw.txt") &
    (curl -s "https://api.hackertarget.com/hostsearch/?q=$target_domain" | grep -oE "[a-zA-Z0-9._-]+\.$target_domain" >> "subs/passive_raw.txt") &
    (curl -s "https://jldc.me/anubis/subdomains/$target_domain" | grep -oE "[a-zA-Z0-9._-]+\.$target_domain" >> "subs/passive_raw.txt") &
    (curl -s "https://urlscan.io/api/v1/search/?q=$target_domain" | grep -oE "[a-zA-Z0-9._-]+\.$target_domain" >> "subs/passive_raw.txt") &
    
    wait
    
    echo "[+] Running subfinder..."
    subfinder -d "$target_domain" --all --silent >> "subs/passive_raw.txt"
    
    sort -u "subs/passive_raw.txt" -o "subs/passive_unique.txt"
    echo -e "${GREEN}[+] Passive enumeration complete. Found $(wc -l < "subs/passive_unique.txt") subdomains.${NC}"
}

dns_bruteforce() {
    echo "[+] Starting DNS brute forcing with puredns..."
    if [ ! -f "$DNS_2M" ]; then
        echo -e "${YELLOW}[!] Brute force wordlist $DNS_2M not found, skipping.${NC}"
        return
    fi
    puredns bruteforce "$DNS_2M" "$target_domain" -r "$RESOLVERS" -w "subs/dns_bf_raw.txt" --skip-wildcard-filter --skip-validation &> /dev/null
    echo -e "${GREEN}[+] Brute force complete.${NC}"
}

dns_permutations() {
    echo "[+] Starting permutations with gotator..."
    if [ ! -f "subs/dns_bf_raw.txt" ] && [ ! -f "subs/passive_unique.txt" ]; then
        echo -e "${YELLOW}[!] No initial subdomains for permutations, skipping.${NC}"
        return
    fi
    
    cat "subs/passive_unique.txt" "subs/dns_bf_raw.txt" 2>/dev/null | sort -u > "subs/temp_for_perm.txt"
    gotator -sub "subs/temp_for_perm.txt" -perm "$PERM_LIST" -mindup -fast -silent | sort -u > "subs/permutations_raw.txt"
    rm "subs/temp_for_perm.txt"
    echo -e "${GREEN}[+] Permutations complete.${NC}"
}

tls_probing() {
    echo "[+] Starting TLS probing with cero..."
    cero "$target_domain" | sed 's/^\*\.//' | grep "\." | grep "\.$target_domain$" | sort -u > "subs/tls_probing_raw.txt"
    echo -e "${GREEN}[+] TLS probing complete.${NC}"
}

scraping_js() {
    echo "[+] Scraping JS files for subdomains..."
    # We need resolved hosts first for scraping
    cat "subs/"*_raw.txt "subs/passive_unique.txt" 2>/dev/null | sort -u > "subs/all_potential.txt"
    puredns resolve "subs/all_potential.txt" -r "$RESOLVERS" -w "subs/all_resolved_temp.txt" --skip-wildcard-filter --skip-validation &> /dev/null
    
    cat "subs/all_resolved_temp.txt" | httpx -random-agent -retries 2 -silent -o "subs/live_for_scraping.txt" &> /dev/null
    
    if [ ! -s "subs/live_for_scraping.txt" ]; then
        echo -e "${YELLOW}[!] No live hosts found for scraping.${NC}"
        return
    fi
    
    gospider -S "subs/live_for_scraping.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "subs/gospider_raw.txt"
    
    # Extracting subdomains from gospider output
    sed -i '/^.\{2048\}./d' "subs/gospider_raw.txt" # Remove huge lines
    cat "subs/gospider_raw.txt" | grep -oE "https?://[^ ]+" | sed 's/]$//' | unfurl -u domains | grep "$target_domain" | sort -u > "subs/scrap_subs_raw.txt"
    rm "subs/gospider_raw.txt"
    echo -e "${GREEN}[+] JS scraping complete.${NC}"
}

finish_work() {
    echo "[+] Aggregating and resolving all discovered subdomains..."
    cat "subs/"*_raw.txt "subs/passive_unique.txt" 2>/dev/null | sort -u > "subs/all_subs_combined.txt"
    
    puredns resolve "subs/all_subs_combined.txt" -r "$RESOLVERS" -w "all_subs_resolved.txt" --skip-wildcard-filter --skip-validation &> /dev/null
    
    echo "[+] Checking live hosts..."
    cat "all_subs_resolved.txt" | httpx -random-agent -retries 2 --silent -o "filtered_hosts.txt" &> /dev/null
    
    echo -e "${GREEN}[+] Done! Results saved to all_subs_resolved.txt and filtered_hosts.txt${NC}"
}

# --- Execution Flow ---

check_tools
setup_dir

options='''
Choose what you wanna do?
[1] Passive recon only
[2] Active recon only (Brute forcing, Permutations, Probing)
[3] Normal Recon [Passive + Active without Permutations]
[4] Quick Recon [Passive + TLS Probing + Scraping]
[5] Full recon [All Techniques]
'''

echo -e "${BLUE}$options${NC}"
read -p "Enter your choice: " choice

case $choice in
    1)
        passive_recon
        ;;
    2)
        dns_bruteforce
        dns_permutations
        tls_probing
        ;;
    3)
        passive_recon
        dns_bruteforce
        tls_probing
        scraping_js
        ;;
    4)
        passive_recon
        tls_probing
        scraping_js
        ;;
    5)
        passive_recon
        dns_bruteforce
        dns_permutations
        tls_probing
        scraping_js
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

finish_work
echo "[+] All tasks finished."