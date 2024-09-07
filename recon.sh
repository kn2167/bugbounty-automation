#!/bin/bash

WORDLIST_PATH="$HOME/wordlist/fuzz4bounty/fuzz4bounty"
NUCLEI_TEMPLATE="$HOME/nuclei-templates/"

# Check if the target file is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <targets_file>"
  exit 1
fi

TARGETS_FILE=$1
# check if the the scope directory exist
#if [[ -z  ]]; then
#  command ...
#fi

# Step 1: Passive Recon - Gather subdomains using Amass, Subfinder
echo "[+] Step 1: Gathering subdomains passively"
for TARGET in $(cat $TARGETS_FILE); do
  echo "[*] Gathering for $TARGET"
  amass enum -passive -d $TARGET -o subdomains_amass_$TARGET.txt
  subfinder -d $TARGET -silent -o subdomains_subfinder_$TARGET.txt

  # Combine subdomains
  cat subdomains_amass_$TARGET.txt subdomains_subfinder_$TARGET.txt | sort -u >subdomains_$TARGET.txt
  echo "[+] Subdomains for $TARGET saved to subdomains_$TARGET.txt"
done

# Step 2: Active Recon - Check live domains, look for potential takeovers
echo "[+] Step 2: Checking live domains and potential takeovers"
for TARGET in $(cat $TARGETS_FILE); do
  echo "[*] Checking live domains for $TARGET"
  httpx -silent -l subdomains_$TARGET.txt -o live_domains_$TARGET.txt
  echo "[+] Live domains for $TARGET saved to live_domains_$TARGET.txt"

  echo "[*] Checking for possible takeovers for $TARGET"
  subzy --targets subdomains_$TARGET.txt --hide_fails --output takeoverable_$TARGET.txt
  echo "[+] Possible subdomain takeovers for $TARGET saved to takeoverable_$TARGET.txt"
done

# Step 3: Extract URLs & endpoints using Gau, then classify juicy data
echo "[+] Step 3: Extracting URLs and classifying juicy data"
for TARGET in $(cat $TARGETS_FILE); do
  echo "[*] Extracting URLs for $TARGET"
  cat live_domains_$TARGET.txt | gau >urls_$TARGET.txt
  echo "[+] URLs for $TARGET saved to urls_$TARGET.txt"

  # Classify juicy URLs using grep
  grep -E "(\.php|\.aspx|\.jsp|login|admin)" urls_$TARGET.txt >juicy_urls_$TARGET.txt
  echo "[+] Juicy URLs for $TARGET saved to juicy_urls_$TARGET.txt"
done

# Step 4: Filter JS files and search for API keys and secrets
echo "[+] Step 4: Searching for JS files and extracting secrets"
for TARGET in $(cat $TARGETS_FILE); do
  echo "[*] Searching JS files for $TARGET"
  grep "\.js$" urls_$TARGET.txt >js_files_$TARGET.txt
  echo "[+] JS files for $TARGET saved to js_files_$TARGET.txt"

  # Download JS files and look for secrets
  for js in $(cat js_files_$TARGET.txt); do
    echo "[*] Downloading $js"
    curl -s $js -o "$(basename $js)"
  done
  echo "[*] Searching for API keys and secrets in JS files"
  grep -E "api_key|secret|token" --*.js >"secrets_$TARGET.txt"
  echo "[+] Secrets for $TARGET saved to secrets_$TARGET.txt"
done

# Step 5: Use Nuclei and Jaeles to scan for vulnerabilities
echo "[+] Step 5: Scanning for vulnerabilities with Nuclei and Jaeles"
for TARGET in $(cat $TARGETS_FILE); do
  echo "[*] Running Nuclei scans for $TARGET"
  nuclei -l live_domains_$TARGET.txt -t $NUCLEI_TEMPLATE -t cves/ -s low, medium, high, critical -mr 4 -r $HOME/1k-resolvers.txt -o nuclei_scan_$TARGET.txt
  echo "[+] Nuclei vulnerabilities scan results for $TARGET saved to nuclei_scan_$TARGET.txt"

  echo "[*] Running Jaeles scans for $TARGET"
  jaeles scan -U live_domains_$TARGET.txt -G -o jaeles_scan_$TARGET
  echo "[+] Jaeles vulnerabilities scan results for $TARGET saved to jaeles_scan_$TARGET"
done

# Step 6: Search for sensitive files
echo "[+] Step 6: Searching for sensitive files"
for TARGET in $(cat $TARGETS_FILE); do
  for domain in $(cat live_domains_$TARGET.txt); do
    echo "[*] Searching for sensitive files on $domain"
    curl -s $domain/robots.txt -o robots_$domain.txt
    curl -s $domain/sitemap.xml -o sitemap_$domain.txt
  done
  echo "[+] Sensitive files for $TARGET saved"
done

# Step 7: Directory brute-forcing using Feroxbuster
echo "[+] Step 7: Brute-forcing directories with Feroxbuster"
for TARGET in $(cat $TARGETS_FILE); do
  echo "[*] Brute-forcing directories for $TARGET"
  feroxbuster --url https://$TARGET -A -s 200,302 -x html,pdf,js,jsx,php,asp,aspx,doc,docx,txt,xls,xlsx,json,yaml,yml,toml,tsx --smart --extract-links -w $WORDLIST_PATH/hfuzz.txt -o feroxbuster_results_$TARGET.txt
  echo "[+] Directory brute-forcing results for $TARGET saved to feroxbuster_results_$TARGET.txt"
done

echo "[+] Automation complete!"
