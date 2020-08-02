# Myrecon
personal recon script for bug bounty


## Modified this after a long time..

Make sure you run install.sh with sudo privileges.


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

You need to give token using "-t" flag for scrapping subdomains from github. "Token without any permission"

# C tool implemented in this script

`massdns`

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

`hakcheckurl`

`shuffledns`

# Python tools Implemented in this script


`smuggler`

`github-subdomains.py`

`interlace`

`cloud_enum`

`CRLF-Injection-Scanner`

`Linkfinder`

`Arjun`

`tplmap`

`sqlmap from github`

`pentest-tools`

`gitGraber`

`dnsvalidator`

`altdns`

# Features 
added support to call specific modules. Multiple modules can be called using comma separated values.(e.g: -m subdomain,crlf) 

date-wise folder creation to differentiate your past recon.

added support to kill the freezed process automatically.

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

`gitrecon: github recon for sensitive information disclosure`


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
bash install.sh

# Where-to-use
I recommend to use VPS as it will create a lot of traffic and will take more than 8hr to complete.
Use my referral link to get 100$ credit on digital ocean for 60 days

`https://m.do.co/c/7879a6363311`

# How-to-use
1) Basic scan

`bash myrecon.sh -d hackerone.com -b blindxss -s ssrf -w wordlist`

2) Using module

`bash myrecon.sh -d hackerone.com -m subdomain -b blindxss -s ssrf -w wordlist -t github_token`


## Note
Use -f flag only with -m flag..
script will create subfolder date-wise and if you want to scan specific module with the specific data you collected on certain day pass the subfolder as an argument.

example:
you ran the script on hackerone.com on date 06/07/2020.
you decided to scan again on 07/07/2020.
Two folder will be created under hackerone.com directory.

Now you want to scan for vulnerabilities on data you collected on 06/07/2020 use following command.

`bash myrecon.sh -d hackerone.com -m vulnscan -b [yourdomain] -s [yourdomain] -f recon-2020-07-06`

# TO-DO
- [ ] Make a HTML report.
- [x] Improve specific module functionality.
- [x] Take arguments from command line for wordlist, blind-xss domain, ssrf domain.
- [ ] May be more clear script.
- [x] DNS brute-Forcing.
- [ ] Slack and/or telegram notification.
- [x] Request smuggling.
- [x] Github recon.
- [x] DNS bruteforcing using alterations.
- [x] Added support to kill the freezed process automatically
- [x] Added support to call multiple modules

# Want-to-Contribute?
Create a pull request for suggestions,bugs.

