#!/bin/bash
clear
banner=`figlet -f slant myrecon`
echo -e "\e[93;1m${banner}" 
echo -e "			\e[31;1m A script by Shubham Chaskar"

echo ""
current=`pwd`



vhostscan()
{
   echo -e "\e[92m Let's scan some virtual host.."
   sleep 3
   for domain in `cat "$domain"_unique.txt`
   do
	gobuster vhost -u "$domain" -t 100 -timeout 30 -v -w /usr/share/wordlists/virtual-host-scanning.txt -o vhost.txt
   done
   cp vhost.txt ./"$domain"/"$subdirectory"/fuzzing/
   rm vhost.txt


}
portscan()
{

   echo -e "\e[92m Masscan will start in some time.."
   sleep 3
   iptables -A INPUT -p tcp --dport 61000 -j DROP    #some problem with masscan
   masscan -iL "$domain"_ip.txt -p0-65535 --rate 100000 --banners --source-port 61000 -v -oG "$domain"_masscan.txt
   echo -e "\e[31m Masscan completed.."
   echo -e "\e[92m Nmap will start to grab banner.."
   sleep 3
   touch "$domain"_banner.txt
   for ip in `cat "$domain"_sorted_ip.txt
   do
	nmap -sV --script=banner "$ip" | sed '$d' | sed '$d' >> "$domain"_banner.txt
	echo "**************************************************************************************************" >> "$domain"_banner.txt
   done
   echo -e "\e[92m NSE banner grabbing completed.."
   vhostscan
}


ipresolve()
{
   echo -e "\e[92m Now resolving ip for port scanning"
   sleep 3
   touch "$domain"_ip.txt
   cp "$domain"_unique.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/fuzzing/
   for ip in `cat "$domain"_unique.txt
   do
	host "$ip" | cut -d " " -f 4 | sed 's/alias//g' | sed 's/CNAME//g' | sed 's/address//g' | sed 's/^$/d' >> "$domain"_ip.txt
	cat "$domain"_ip.txt
   done
   echo -e "\e[92m Sorting file for unqiue ip"
   cat "$domain"_ip.txt | sort -u > "$domain"_sorted_ip.txt
   rm "$domain"_ip.txt
   echo -e "\e[92m File sorted successfully and passing to port scanning"
   sleep 3
   portscan
}


subdomain()
{
   echo ""
   echo "\e[31m Sublist3r will start in 5 seconds.."
   sleep 5
   clear
   python3 /root/scripts/bounty/Sublist3r/sublist3r.py -d "$domain" -t 50 -o ./"$domain"/"$subdirectory"/subdomains/sublist3r.txt -v
   echo ""
   echo -e "\e[92m Sublist3r scan completed.."
   echo ""
   echo -e "\e[93m Amass scan will start in 5 seconds"
   sleep 5
   echo -e "\e[31m Amass scan started"
   amass -passive -d "$domain" -o ./"$domain"/"$subdirectory"/subdomains/amass_result.txt
   echo -e "\e[92m Amass scan completed"
   echo ""
   echo -e "\e[92m File saved as amass_result.txt"
   echo ""
   echo -e "\e[93m Subfinder scan will start in 5 seconds.."
   sleep 5
   subfinder -d "$domain" -t 100 -b -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-20000.txt -o ./"$domain"/"$subdirectory"/subdomains/subfinder_result.txt
   echo -e "\e[92m Subfinder scan completed"
   echo -e "\e[92m File saved as subfinder_result.txt"
   echo ""
   echo -e "\e[93m Knock will start scanning in 5 seconds"
   sleep 5
   knockpy -c "$domain"
   echo -e "\e[92m Filtering the output"
   cat *.csv | cut -d "," -f 4 > ./"$domain"/"$subdirectory"/subdomains/knock_domains.txt  #taking only domain name
   cat *.csv | cut -d "," -f 1 > ./"$domain"/"$subdirectory"/subdomains/knock_ip.txt   #taking only ip's
   echo -e "\e[92m knock scan completed"
   echo -e "\e[92m File saved as knock_domains"
   echo ""
   echo -e "\e[92m compiling unique results for massdns to scan"
   cat ./"$domain"/"$subdirectory"/subdomains/sublist3r.txt > ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/amass_result.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/subfinder_result.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/knock_domains.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/"$domain".txt | sort -u > ./"$domain"/"$subdirectory"/subdomains/"$domain"_unique.txt

   if [ -e ./"$domain"/"$subdirectory"/subdomains/"$domain"_unique.txt ]
   then
	echo -e "\e[92m file compiled,sorted successfully"
   else
	echo -e "\e[31m file not found..can't proceed"
	exit 1
   fi
   echo ""
   sleep 5
   cp ./"$domain"/"$subdirectory"/subdomains/"$domain"_unique.txt "$current"
   echo -e "\e[92m passing file to massdns for active DNS resolution"
   massdns -r /root/scripts/bounty/massdns/lists/resolvers.txt "$domain"_unique.txt -t A -o S -w ./"$domain"/"$subdirectory"/subdomains/massdns.txt
   cat ./"$domain"/"subdirectory"/subdomains/massdns.txt | cut -d " " -f 3 > ./"$domain"/"$subdirectory"/subdomains/massdns_ip.txt
   cat ./"$domain"/"$subdirectory"/subdomains/massdns.txt | cut -d " " -f 1 > ./"$domain"/"$subdirectory"/subdomains/massdns_domain.txt
   altdns -i ./"$domain"/"$subdirectory"/subdomains/massdns_domain.txt -t 50 -w /root/scripts/bounty/altdns/words.txt -o ./"$domain"/"$subdirectory"/subdomains/altdns.txt
   cp ./"$domain"/"$subdirectory"/subdomains/altdns.txt "$current"
   massdns -r /root/scripts/bounty/massdns/lists/resolvers.txt altdns.txt -t A -o S -w ./"$domain"/"$subdirectory"/subdomains/massdns_altdns.txt
   echo -e "\e[92m Compiling results in File"
   cat ./"$domain"/"$subdirectory"/subdomains/massdns_altdns.txt | cut -d " " -f 1 >> ./"$domain"/"$subdirectory"/subdomains/"$domain"_unique.txt
   cat ./"$domain"/"$subdirectory"/subdomains/massdns_altdns.txt | cut -d " " -f 3 >> ./"$domain"/"$subdirectory"/subdomains/massdns_ip.txt
   rm *.csv
   cd ./"$domain"/"$subdirectory"/subdomains
   cp "$domain"_unique.txt aquatone/
   rm -rf amass_output sublist3r.txt amass_result.txt subfinder_result.txt knock_domain.txt massdns.txt massdns_domain.txt altdns.txt massdns_altdns.txt
   cd ./"$domain"/"$subdirectory"/subdomains/aquatone
   echo -e "\e[92m Passing file to aquatone"
   sleep 3
   sed -i 's/^/https:\/\//' "$domain"_unique.txt
   cat "$domain"_unique.txt | aquatone -debug
   cd -
   echo -e "\e[92m Script Now scan for subdomain takeover"
   sleep 2
   cp "$domain"_unique.txt /root/go/src/github.com/haccer/subjack/
   cd /root/go/src/github.com/haccer/subjack
   echo -e "\e[92m Directory changed.."
   echo -e "\e[92m Subjack is in action.."
   sleep 2
   ./main -c fingerprints.json -t 50 -timeout 20 -v -w "$domain"_unique.txt -o subjack_result.txt
   cp subjack_result.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/subdomains/
   rm subjack_result.txt "$domain"_unique.txt
   cd -
   cp "$domain"_unique.txt /root/go/src/github.com/Ice3man543/SubOver/
   cd /root/go/src/github.com/Ice3man543/SubOver/
   echo -e "\e[92m Directory changed..."
   echo -e "\e[92m Subover is in action..."
   sleep 2
   ./SubOver -l "$domain"_unique.txt -t 100 -timeout 30 -v -o "$domain"_subover.txt
   cp "$domain"_subover.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/subdomains/
   rm "$domain"_subover.txt "$domain"_unique.txt
   cd -
   ipresolve

}

helpFunction()
{
   echo ""
   echo "Usage: $0 -d [domain name(google.com)] "
   echo -e "\t-d domain name for the recon"
   exit 1 # Exit script after printing help


subdirectory=recon-$(date +"%Y-%m-%d")

while getopts "d:h:" opt
do
   case "$opt" in
      d ) domain="$OPTARG" ;;
      ? ) helpFunction ;; # Print helpFunction in case parameter is non-existent
   esac
done

if [ -d "./$domain" ]
then
   echo -e "\e[91m Target already scanned"
else
   mkdir ./"$domain"
   mkdir ./"$domain"/"$subdirectory"
   mkdir ./"$domain"/"$subdirectory"/subdomains
   mkdir ./"$domain"/"$subdirectory"/subdomains/aquatone
   mkdir ./"$domain"/"$subdirectory"/fuzzing/
fi

if [ -z "$domain" ]
then
   echo -e "\e[91m Pass the domain name";
   helpFunction
else
   subdomain
fi


