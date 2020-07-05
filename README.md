# Myrecon
personal recon script for bug bounty


# Modified this after a long time..

Make sure you run install.sh with sudo privileges.

# You need to change a script as argument support is limited.

```
1) Open myrecon.sh using your favourite text editor.
2) Search the term "dalfox" and put your blind-xss domain inside quotes.
3) Search the term "ss" and put your ssrf domain without quotes.
4) Search the term "your-wordlist" and replace it with the wordlist you want to bruteforce directory and files.
5) If you wish you can change wordlists os s3scan,(OPTIONAL) to do that you can copy your wordlist to /root/scripts/bounty/cloud_enum/ and change the file name by searching the term "permutations.txt"
```

# Prerequisites


`GO 1.13+`

`Python3.6 +`

`python2.7`

`pip2`

`pip3`

`rust`

`make`

`perl`

`gf-patterns`


Your GO, rust, python3 path must be set. make sure you can run GO tools directly without calling it from installation directory!!


# Rust tool implemented in this script

`
findomain
`

# GO Tools Implemented in this script


`assetfinder`

`subfinder`

`amass`

`httprobe`

`aquatone`

`subjack`

`Subover`

`tko-subs`

`naabu`

`ffuf`

`Waybackurl`

`gau`

`gospider`

`jaeles`

`nuclei`

`kxss`

`dalfox`

`gf`

`qsreplace`

`unfurl`


# Python tools Implemented in this script


`github-subdomains.py`

`interlace`

`cloud_enum`

`CRLF-Injection-Scanner`

`Linkfinder`

`Arjun`

`tplmap`

`sqlmap from github`


# Features 
added support to call specific modules

# Modules included

`subdomain: Subdomain gathering + probing + screenshot`

`portscan: full portscan + nmap service detection on found ports`

`dirbruteforce: directory bruteforce`

`s3scan: scan buckets`

`crlf: srlf injection scanner`

`linkfinder: finding js files and endpoints`

`wayback: getting all URLs from wayback machine`

`spider: crawl and filter all data`

`vulnscan: sql, xss, CVE scanning`


# Note
To call specific modules, you must have ran the script at least one time with succesful completion of subdomain module.

# Example
you ran the script using following command and you notice that after s3scan script failed due to any internet connectivity and/or any other issue.

`bash myrecon.sh -d hackerone.com`

Now if you want you can resume from crlf --> linkfinder --> wayback --> spider --> vulnscan by using following command.(One-by-one) :(

`bash myrecon.sh -d hackerone.com -m crlf`

# Note 
half of the vulnscan module is totally dependent on wayback and spider module.
Only single module can be run at a time if flag has been provided.

# Note
Updating Nuclei templates?
This script is saving nuclei templates at /root/nuclei-templates/
after running install.sh it will create a folder called "all" and will copy all templates inside that directory.
ProjectDiscovery is regularly updating their repo with new templates.
To update your nuclei templates follow these commands.

```
cd /root/
nuclei -update-templates
cd nuclei-templates/
mkdir all
cp -at ./all/ ./**/*.yaml
```

All templates will be copied to all directory and will be used by myrecon.sh in future.

# Installation

Make sure $GOPATH has been set in .bashrc file and you can run go tools from anywhere. (Important)

`git clone https://github.com/unstabl3/Myrecon.git`

`cd Myrecon/`

`bash install.sh`

`cd ../ && mv Myrecon/ /root/scripts/bounty/ && cd /root/scripts/bounty/Myrecon/`

# Updating the script
git pull

# Where-to-use
I recommend to use VPS as it will create a lot of traffic and will take more than 8hr to complete.
Use my referral link to get 100$ credit on digital ocean for 60 days

`https://m.do.co/c/7879a6363311`

# How-to-use
1) Basic scan

`bash myrecon.sh -d hackerone.com -b blindxss -s ssrf -w wordlist`

2) Using module

`bash myrecon.sh -d hackerone.com -m subdomain -b blindxss -s ssrf -w wordlist`


# TO-DO
1) Make a HTML report.
2) Improve specific module functionality.
~~3) Take arguments from command line for wordlist, blind-xss domain, ssrf domain.~~
4) May be more clear script.
5) DNS brute-Forcing.
6) Slack and/or telegram notification.
7) Request smuggling.
8) Github recon.

# Want-to-Contribute?
Create a pull request for suggestions,bugs.
