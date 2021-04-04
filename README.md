## Myrecon
personal recon script for bug bounty


Make sure you run install.sh with sudo privileges.


### Prerequisites

You need to configure gitgrabber and slackcat.


<details open>
<summary>C tool implemented in this script!</summary>
<ul>
<li> massdns</li>
<ul>
</details>

<details open>
<summary>Rust tool implemented in this script!</summary>
<ul>
<li> findomain</li>
<ul>
</details>

<details open>
<summary>Go tools implemented in this script!</summary>
<ul>
<li> assetfinder</li>
<li> subfinder</li>
<li> amass</li>
<li> aquatone</li>
<li> subjack</li>
<li> subover</li>
<li> tko-subs</li>
<li> naabu</li>
<li> ffuf</li>
<li> Waybackurl</li>
<li> gospider</li>
<li> jaeles</li>
<li> nuclei</li>
<li> kxss</li>
<li> gf</li>
<li> dalfox</li>
<li> qsreplace</li>
<li> unfurl</li>
<li> hakcheckurl</li>
<li> shuffledns</li>
<li> crlfuzz</li>
<ul>
</details>

<details open>
<summary>Python tools implemented in this script!</summary>
<ul>
<li> smuggler</li>
<li> github-subdomains.py</li>
<li> interlace</li>
<li> cloud_enum</li>
<li> Linkfinder</li>
<li> Arjun</li>
<li> tplmap</li>
<li> sqlmap</li>
<li> pentest-tools</li>
<li> dnsvalidator</li>
<li> gitGraber</li>
<li> altdns</li>
<ul>
</details>
  
## Features 

* added support to call specific modules. Multiple modules can be called using comma separated values.(e.g: -m subdomain,crlf) 

* date-wise folder creation to differentiate your past recon.

* Support to kill the freezed process automatically.

* Build your own scan engine

* More flexibility in your command arguments.

* Exclude out-of-scope subdomains. (-e blog.hackerone.com,beta.hackerone.com)

* Error Logging has been implemented.

## Modules included

* subdomain: Subdomain gathering + Exclude(if any) + probing + screenshot

* portscan: full portscan + nmap service detection on found ports

* dirbruteforce: directory bruteforce

* s3scan: scan buckets

* crlf: srlf injection scanner

* linkfinder: finding js files and endpoints

* wayback: getting all URLs from wayback machine

* spider: crawl and filter all data

* vulnscan: sql, xss, CVE scanning

* gitrecon: github recon for sensitive information disclosure

### Note
Modules flow is necessary! you can't call vulnscan before wayback and/or spider.
To call specific modules, you must have ran the script at least one time with succesful completion of subdomain module.

### Example
you ran the script using following command and you notice that after s3scan script failed due to any internet connectivity and/or any other issue.

`bash myrecon.sh -d hackerone.com`

Now You can continue where you left of by following command

`bash myrecon.sh -d hackerone.com -f recon-2020-07-06 -m crlf,linkfinder,wayback,vulnscan`

### Note 
half of the vulnscan module is totally dependent on wayback and spider module.

`bash myrecon.sh -d hackerone.com -m subdomain,wayback,spider,vulnscan`


## Installation

Make sure $GOPATH has been set in .bashrc file and you can run go tools from anywhere. (Important)

```
git clone https://github.com/unstabl3/Myrecon.git
cd Myrecon/
bash install.sh
cd ../ && mv Myrecon/ /root/scripts/bounty/ && cd /root/scripts/bounty/Myrecon/
```
#### Updating the script


```
git pull
bash install.sh
```

## Where-to-use
I recommend to use VPS as it will create a lot of traffic and will take more than 8hr to complete.
Use my referral link to get 100$ credit on digital ocean for 60 days

`https://m.do.co/c/7879a6363311`

### Note
You need to edit a Myrecon/.tokens file with github_token, wordlist, your ssrf domain, your blind xss domain.

The script is flexible. Priority will be given to the command line arguments. If you don't provide command line arguments script will take values from .tokens file


## How-to-use
1) Basic scan using command line arguments.

`bash myrecon.sh -d hackerone.com -b blindxss -s ssrf -w wordlist -e blog.hackerone.com`

2) Using only specific single module.

`bash myrecon.sh -d hackerone.com -m subdomain -b blindxss -s ssrf -w wordlist -t github_token`

3) Basic scan using static values.(value will be taken from .tokens file)

`bash myrecon.sh -d hackerone.com`

### Note
If you want good amount of subdomains configure API for every subdomain tools. (Amass,subfinder,assetfinder,findomain)
Use -f flag only with -m flag..
script will create subfolder date-wise and if you want to scan specific module with the specific data you collected on certain day pass the subfolder as an argument.
A error log file will be generated for every scan and will be stored with respect to time of scan.
Configure gitgrabber properly to get github recon result!

### example:
you ran the script on hackerone.com on date 06/07/2020.
you decided to scan again on 07/07/2020.
Two folder will be created under hackerone.com directory.

Now you want to scan for vulnerabilities on data you collected on 06/07/2020 use following command.

`bash myrecon.sh -d hackerone.com -m vulnscan -b [yourdomain] -s [yourdomain] -f recon-2020-07-06`

or if you have .tokens properly configured

`bash myrecon.sh -d hackerone.com -m vulnscan -f recon-2020-07-06`


## Slacking

Notifications will be send to slack using "Slackcat" tool! You need to create Slack channel in your workspace and enable incoming webhook! Copy the webhook and save it in the .tokens file.
If you wish you can give webhook as a command-line argument using "-n" flag.

<details open>
<summary>The following recon data will be sent to your slack channel!</summary>
<ul>
<li> Portscan</li>
<li> Both open and protected S3 buckets</li>
<li> Both open and proteceted google buckets</li>
<li> Both open and protected azure blobs</li>
<li> Nuclei Results</li>
<li> jaeles result</li>
<li> Possible XSS</li>
<li> Possible SSTI</li>
<li> Possible SQLi</li>
<li> Possible Open Redirect</li>
<li> Possible LFI</li>
<li> Possible HTTP request smuggling</li>
<ul>
</details>
  
Remaining modules data will be sent if and only if filteration of a output is possible.

## TO-DO
- [ ] Make a HTML report.
- [x] Improve specific module functionality.
- [x] Take arguments from command line for wordlist, blind-xss domain, ssrf domain.
- [X] Take arguments from file.
- [ ] May be more clear script.
- [ ] DNS brute-Forcing.
- [x] Slack and/or telegram notification.
- [x] Request smuggling.
- [x] Github recon.
- [ ] DNS bruteforcing using alterations.
- [x] Added support to kill the freezed process automatically
- [x] Added support to call multiple modules
- [x] Added error logging.
- [x] Added support to exclude subdomains.
- [ ] Compare results with previous scan and send only new data to slack.

## Want-to-Contribute?
Create a pull request for suggestions,bugs.

# Disclaimer!
* You expressly understand and agree that I shall not be liable for any damages or losses resulting from your use of this script or third-party products that multiple tools(in this script) use it.

I will not be in charge of any and have/has no responsibility for any kind of:

* Unlawful or illegal use of this script.
* Legal or Law infringement (acted in any country, state, municipality, place) by third parties and users.
* Act against ethical and / or human moral, ethic, and peoples and cultures of the world.
* Malicious act, capable of causing damage to third parties, promoted or distributed by third parties or the user through this script.






