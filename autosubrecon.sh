#!/bin/bash

# Make directories if they don't exist
rm -r subs/
mkdir -p "subs"
mkdir -p "Wordlists/dns"


ascii_art=''' 
 /\   _|_ _ (~   |_ |~) _  _ _  _ 
/~~\|_|| (_)_)|_||_)|~\(/_(_(_)| |
                        
                by @h0tak88r
'''
echo  "$ascii_art"

# Set the target domain
target_domain="$1"

# Check if target_domain is provided
if [ -z "$target_domain" ]; then
  echo "[+] usage $0 domain.com "
  exit 1
fi

# Passive subdomain enumeration
echo  "[+] Let's start with passive subdomain enumeration!	 "

# URLs to fetch subdomains from various sources
urls=(
    "https://rapiddns.io/subdomain/$target_domain?full=1#result"
    "http://web.archive.org/cdx/search/cdx?url=*.$target_domain/*&output=text&fl=original&collapse=urlkey"
    "https://crt.sh/?q=%.$target_domain"
    "https://crt.sh/?q=%.%.$target_domain"
    "https://crt.sh/?q=%.%.%.$target_domain"
    "https://crt.sh/?q=%.%.%.%.$target_domain"
    "https://otx.alienvault.com/api/v1/indicators/domain/$target_domain/passive_dns"
    "https://api.hackertarget.com/hostsearch/?q=$target_domain"
    "https://urlscan.io/api/v1/search/?q=$target_domain"
    "https://jldc.me/anubis/subdomains/$target_domain"
    "https://www.google.com/search?q=site%3A$target_domain&num=100"
    "https://www.bing.com/search?q=site%3A$target_domain&count=50"
)

# Fetch subdomains from various sources concurrently
echo  "[+] Getting $target_domain subdomains using [crt.sh,rapiddns,alienvault,hackertarget,urlscan,jldc.me,google,bing]"

for url in "${urls[@]}"; do
    curl -s "$url" | grep -o  '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.'"$target_domain"'' >> "subs/passive.txt"
done

wait

echo  "[+] Removing duplicates....."
echo  "[+] Saving to quick_passive.txt"

cat "subs/passive.txt" | sort -u > "subs/quick_passive.txt"
rm "subs/passive.txt"

echo  "[+] Using subfinder for passive subdomain enumeration "
subfinder -d $target_domain --all --silent > "subs/subfinder.txt"

echo  "[+] That's it, we are done with passive subdomain enumeration !"

# Active subdomain enumeration
echo  "[+] Start active subdomain enumeration!"

# 1. DNS Brute Forcing using puredns
echo  "[+] DNS Brute Forcing using puredns"
puredns bruteforce "Wordlists/dns/dns_2m.txt" "$target_domain" -r "Wordlists/dns/valid_resolvers.txt" -w "subs/dns_bf.txt" --skip-wildcard-filter --skip-validation &> /dev/null

echo  "[+] resolving brute forced subs...."
puredns resolve "subs/dns_bf.txt" -r "Wordlists/dns/valid_resolvers.txt" -w "subs/dns_bf_resolved.txt"  --skip-wildcard-filter --skip-validation &> /dev/null

# 2. Permutations using gotator
echo  "[+] Permutations using gotator"
gotator -sub "subs/dns_bf_resolved.txt" -perm "Wordlists/dns/dns_permutations_list.txt" -mindup -fast -silent | sort -u > "subs/permutations.txt"

# 3. TLS probing using cero
echo  "[+] TLS probing using cero"
cero "$target_domain" | sed 's/^*.//' | grep  "\." | sort -u |  grep ".$target_domain$" > "subs/tls_probing.txt"

# 4. Scraping (JS/Source) code
echo  "[+] Scraping JS Source code "
cat "subs/"* | sort -u > "subs/filtered_subs.txt"
cat "subs/filtered_subs.txt" | httpx -random-agent -retries 2 -o "subs/filtered_hosts.txt" &> /dev/null

# Crawling using gospider
echo  "[+] Crawling for js files using gospider"
gospider -S "subs/filtered_hosts.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "subs/gospider.txt"

# Extracting subdomains from JS Files
echo  "[+] Extracting Subdomains......"
sed -i '/^.\{2048\}./d' "subs/gospider.txt"
cat "subs/gospider.txt" | grep o 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep "$target_domain" | sort -u > "subs/scrap_subs.txt"
rm "subs/gospider.txt"

# Done with active subdomain enumeration
echo  "[+] Done with Active subdomain enumeration!"

# Finishing our subdomain enumeration
echo  "[+] Finishing our work and filtering out the subdomains"

# Combining all the subdomains
echo  "[+] Removing duplicates from subdomains"
cat "subs/"* | sort -u > "subs/all_subs_filtered.txt"

# Filtering out the subdomains
echo  " [+] Resolving subdomains and save the output to all_subs_resolved.txt"
puredns resolve "subs/filtered_subs.txt" -r "Wordlists/dns/valid_resolvers.txt" -w "subs/all_subs_resolved.txt" --skip-wildcard-filter --skip-validation &> /dev/null

# Running httpx on the subdomains
echo " [+] web probing using httpx and save the output to filtered_hosts.txt"
cat "subs/all_subs_resolved.txt" | httpx -random-agent -retries 2 --silent -o "subs/filtered_hosts.txt"  &> /dev/null

echo "[+] Thats it we are done with subdomain enumeration!"
