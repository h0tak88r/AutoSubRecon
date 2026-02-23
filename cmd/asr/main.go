package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/h0tak88r/AutoSubRecon/pkg/crawl"
	"github.com/h0tak88r/AutoSubRecon/pkg/dns"
	"github.com/h0tak88r/AutoSubRecon/pkg/http"
	"github.com/h0tak88r/AutoSubRecon/pkg/passive"
	"github.com/h0tak88r/AutoSubRecon/pkg/permutations"
	"github.com/h0tak88r/AutoSubRecon/pkg/tls"
	"github.com/h0tak88r/AutoSubRecon/pkg/utils"
)

func main() {
	domain := flag.String("d", "", "Target domain")
	mode := flag.Int("mode", 5, "Recon mode (1-5)")
	wordlist := flag.String("w", "Wordlists/dns/dns_2m.txt", "DNS bruteforce wordlist")
	resolvers := flag.String("r", "Wordlists/dns/valid_resolvers.txt", "DNS resolvers file")
	threads := flag.Int("t", 50, "Number of concurrent threads")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nAvailable Recon Modes:\n")
		fmt.Fprintf(os.Stderr, "  1: Passive Recon Only (subfinder)\n")
		fmt.Fprintf(os.Stderr, "  2: DNS Bruteforce + TLS Probing + Permutations\n")
		fmt.Fprintf(os.Stderr, "  3: Passive + TLS + DNS Bruteforce + HTTP Check + Scraping\n")
		fmt.Fprintf(os.Stderr, "  4: Passive + TLS + HTTP Check + Scraping (No DNS Bruteforce)\n")
		fmt.Fprintf(os.Stderr, "  5: Full Recon (Passive + TLS + DNS Bruteforce + Permutations + HTTP Check + Scraping)\n")
	}
	flag.Parse()

	if *domain == "" {
		flag.Usage()
		os.Exit(1)
	}

	ctx := context.Background()

	// Initialize result directory
	if err := os.MkdirAll("subs", 0755); err != nil {
		log.Fatalf("Failed to create results directory: %v", err)
	}

	var allSubdomains []string

	// 1. Passive Recon (Modes 1, 3, 4, 5)
	if *mode == 1 || *mode == 3 || *mode == 4 || *mode == 5 {
		log.Printf("[INFO] Starting passive recon for %s", *domain)
		pRunner, err := passive.NewRunner(*threads)
		if err != nil {
			log.Fatalf("Failed to create passive runner: %v", err)
		}
		subs, err := pRunner.Enumerate(ctx, *domain)
		if err != nil {
			log.Printf("[ERROR] Passive recon failed: %v", err)
		} else {
			log.Printf("[OK] Found %d passive subdomains", len(subs))
			allSubdomains = append(allSubdomains, subs...)
		}
	}

	// 2. TLS Probing (Modes 2, 3, 4, 5)
	if *mode == 2 || *mode == 3 || *mode == 4 || *mode == 5 {
		log.Printf("[INFO] Starting TLS probing for %s", *domain)
		tlsClient, err := tls.NewClient(*threads)
		if err != nil {
			log.Printf("[ERROR] Failed to init TLS client: %v", err)
		} else {
			subs, err := tlsClient.Probe(ctx, *domain)
			if err != nil {
				log.Printf("[ERROR] TLS probing failed: %v", err)
			} else {
				log.Printf("[OK] Found %d subdomains via TLS", len(subs))
				allSubdomains = append(allSubdomains, subs...)
			}
		}
	}

	// Load resolvers if provided
	var resolverList []string
	if *resolvers != "" {
		if lines, err := utils.ReadLines(*resolvers); err == nil {
			resolverList = lines
		}
	}

	// Initialize DNS client
	dnsClient, err := dns.NewClient(resolverList, *threads)
	if err != nil {
		log.Fatalf("Failed to create DNS client: %v", err)
	}

	// 3. DNS Bruteforce (Modes 2, 3, 5)
	if *mode == 2 || *mode == 3 || *mode == 5 {
		log.Printf("[INFO] Starting DNS bruteforce for %s", *domain)
		if *wordlist != "" {
			words, err := utils.ReadLines(*wordlist)
			if err != nil {
				log.Printf("[ERROR] Failed to read wordlist: %v", err)
			} else {
				subs, err := dnsClient.Bruteforce(ctx, *domain, words)
				if err != nil {
					log.Printf("[ERROR] DNS bruteforce failed: %v", err)
				} else {
					log.Printf("[OK] Found %d subdomains via bruteforce", len(subs))
					allSubdomains = append(allSubdomains, subs...)
				}
			}
		}
	}

	// 4. Permutations (Modes 2, 5)
	if *mode == 2 || *mode == 5 {
		permWordlist := "Wordlists/dns/dns_permutations_list.txt"
		if words, err := utils.ReadLines(permWordlist); err == nil {
			log.Printf("[INFO] Starting permutations for %d subdomains", len(allSubdomains))
			gen := permutations.NewGenerator(words)
			subs := gen.Generate(allSubdomains, *domain)
			log.Printf("[OK] Generated %d permutations", len(subs))
			allSubdomains = append(allSubdomains, subs...)
		}
	}

	// deduplicate subdomains
	allSubdomains = deduplicate(allSubdomains)

	// 5. DNS Resolution
	log.Printf("[INFO] Resolving %d unique subdomains", len(allSubdomains))
	resolvedSubs, err := dnsClient.Resolve(ctx, allSubdomains)
	if err != nil {
		log.Printf("[ERROR] DNS resolution failed: %v", err)
	} else {
		log.Printf("[OK] %d subdomains resolved", len(resolvedSubs))
		utils.WriteLines("all_subs_resolved.txt", resolvedSubs)
	}

	// 6. HTTP Live Check & Scraping (Modes 3, 4, 5)
	log.Printf("[INFO] Checking live hosts")
	httpClient, err := http.NewClient(*threads)
	if err != nil {
		log.Fatalf("Failed to create HTTP client: %v", err)
	}
	liveHosts, err := httpClient.CheckLive(ctx, resolvedSubs)
	if err != nil {
		log.Printf("[ERROR] HTTP check failed: %v", err)
	} else {
		log.Printf("[OK] %d live hosts found", len(liveHosts))
		utils.WriteLines("filtered_hosts.txt", liveHosts)
		
		// 7. Scraping (if applicable)
		if *mode == 3 || *mode == 4 || *mode == 5 {
			log.Printf("[INFO] Scraping live hosts for more subdomains")
			scraper := crawl.NewScraper()
			var scrapedSubs []string
			for _, host := range liveHosts {
				subs, _ := scraper.Extract(ctx, host, *domain)
				scrapedSubs = append(scrapedSubs, subs...)
			}
			scrapedSubs = deduplicate(scrapedSubs)
			log.Printf("[OK] Found %d subdomains via scraping", len(scrapedSubs))
			
			// If we found more, we should probably resolve them too, but 
			// for now let's just add them to the final list
			allSubdomains = append(allSubdomains, scrapedSubs...)
		}
	}

	log.Printf("[DONE] Recon complete. Results saved in all_subs_resolved.txt and filtered_hosts.txt")

}


func deduplicate(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
