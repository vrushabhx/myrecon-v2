#!/bin/bash
clear
banner=`figlet -f slant myrecon`    #without banner there is no script
echo -e "\e[93;1m${banner}" 
echo -e "			\e[31;1m A script by Shubham Chaskar"

echo " "
current=`pwd`
massdns=/root/scripts/bounty/massdns/bin/massdns
altdns=/root/scripts/bounty/altdns/altdns.py
ifconfig wlan0 down
IP=`ifconfig wlan1 | grep "inet " | cut -d ' ' -f 10`


gitrecon()
{
   cd "$current"
   rm *.csv "$domain"_Bunique.txt "$domain"_unique.txt
   git=`echo "$domain" | cut -d "." -f 1`
   echo -e "\e[92m[~] Slurp will be in action.."
   echo "***************************************************************************************"
   cd /root/go/src/github.com/0xbharath/slurp/
   sleep 3
   ./main domain -t "$domain"
   ./main keyword -t "$domain"
   echo -e "\e[92m[~] Slurp completed.."
   echo "***************************************************************************************"
   echo -e "\e[92m[~] gitrob will be in  action.."
   cd /root/go/src/github.com/michenriksen/gitrob/
   ./main -save "$domain"_gitrob -threads 100 "$git"
   cp "$domain"_gitrob "$current"/"$domain"/"$subdirectory"/
}
#screenshot()
#{
#   cd "$current"
 #  echo "**********************************************************************************************"
 #  echo -e "\e[92m[~] It's time to take some screenshots.."
  # echo -e "\e[92m[~] EyeWitness will start in some time.."
  # echo "**********************************************************************************************"
  # cp "$domain"_unique.txt /root/scripts/bounty/EyeWitness/
  # cd /root/scripts/bounty/EyeWitness
  # sleep 1
  # ./EyeWitness.py --web -f "$domain"_unique.txt --threads 100 -d "$domain"_screenshot --no-prompt
  # rm "$domain"_unique.txt
   #cd "$domain"_screenshot
   #rm -rf source jquery-1.11.3.min.js open_ports.csv report.html report_page2.html Requests.csv style.css
   #cd ../
   #cp "$domain"_screenshot /"$current"/"$domain"/"$subdirectory"/subdomains/
#   rm -rf "$domain"_screenshot

#}


wayback()
{
   cd "$current"
   echo "***********************************************************************************************"
   echo -e "\e[92m[~] Going back in time to search some endpoints.."
   echo -e "\e[92m[~] Waybackurl will be in action.."
   echo "***********************************************************************************************"
   cp "$domain"_unique.txt /root/go/src/github.com/tomnomnom/waybackurls/
   cd /root/go/src/github.com/tomnomnom/waybackurls/
   cat "$domain"_unique.txt | ./main -no-subs > waybackurls.txt
   cp waybackurls.txt /"$current"/"$domain"/"$subdirectory"/fuzzing/
   cat waybackurls.txt
   rm waybackurls.txt
   gitrecon
 #  screenshot
}


#filefuzz()
#{
 #  cd "$current"
  # echo "**********************************************************************************************"
   #echo -e "\e[92m[~] Finding some juicy files.."
   #echo -e "\e[92m[~] Meg will start fuzzing.."
   #echo "**********************************************************************************************"
   #cp "$domain"_unique.txt /"$current"/"$domain"/"$subdirectory"/fuzzing/
   #cp paths /"$current"/"$domain"/"$subdirectory"/fuzzing/
   #cd /"$current"/"$domain"/"$subdirectory"/fuzzing/
   #cp "$domain"_unique.txt hosts
   #sed -i 's/^/https:\/\//g' hosts
   #meg -c 100 -v hosts paths meg_output 
   #cd meg_output
   #echo -e "\e[92m[~] Following things found.."
   #cat index | grep "(200 OK)"
   #echo "***********************************************************************************************"
   #cd ../
   #cp -R meg_output /"$current"/"$domain"/"$subdirectory"/fuzzing/
   #rm -rf meg_output
   #wayback
#}


linkfinder()
{
   cd "$current"
   echo "***********************************************************************************************"
   echo -e "\e[92m[~] Finding JS files and endpoints.."
   echo -e "\e[92m[~] Linkfinder will be in action.."
   echo "***********************************************************************************************"
   cp "$domain"_unique.txt /root/scripts/bounty/LinkFinder/
   cd /root/scripts/bounty/LinkFinder/
   touch "$domain"_js_endpoints.txt
   sed -i 's/^/https:\/\//' "$domain"_unique.txt
   for host in `cat "$domain"_unique.txt`
   do
	echo "******************************************************************************************" >> "$domain"_js_endpoints.txt
	echo 					"$host"						>> "$domain"_js_endpoints.txt
	echo "Analysing $host"
	echo "******************************************************************************************" >> "$domain"_js_endpoints.txt
	./linkfinder.py -i "$host" -d -o cli >> "$domain"_js_endpoints.txt
   done
   echo -e "\e[92m[~] Found some endpoints.."
   cp "$domain"_js_endpoints.txt "$current"/"$domain"/"$subdirectory"/fuzzing/
   cat "$domain"_js_endpoints.txt
   rm "$domain"_js_endpoints.txt "$domain"_unique.txt
 #  filefuzz
   wayback
}


#cors()
#{
 #  cd "$current"
  # echo "************************************************************************************************"
  # echo -e "\e[92m[~] Scanning for CORS misconfiguration.."
  # echo -e "\e[92m[~] CORS scanner will be in action.."
  # echo "************************************************************************************************"
  # cp "$domain"_unique.txt /root/scripts/bounty/CORScanner/
  # cd /root/scripts/bounty/CORScanner
  # python cors_scan.py -t 200 -i "$domain"_unique.txt -v -o "$domain"_cors.txt
  # if [ -e "$domain"_cors.txt ]
  # then
#	echo -e "\e[92m[~] Found something interesting.."
 #       echo "**********************************************************************************"
  #      cat "$domain"_cors.txt
   #     echo "**********************************************************************************"
#	cp "$domain"_cors.txt "$current"/"$domain"/"$subdirectory"/fuzzing/
#	rm "$domain"_cors.txt
 #  else
#	echo "**********************************************************************************"
#	echo -e "\e[92m[~] Scanner doesn't found cors misconfiguration.."
#	echo "**********************************************************************************"
 #  fi
  # echo "***************************************************************************************"
  # echo -e "\e[92m[~] CORStest will be in action.."
   #sleep 1
   #cp "$domain"_unique.txt /root/scripts/bounty/CORStest/
   #cd /root/scripts/bounty/CORStest/
   #./corstest.py -v "$domain"_unique.txt
   #echo -e "\e[92m[~] CORStest scan completed.."
   #echo "***************************************************************************************"
   #linkfinder
#}


#crlf()
#{
 #  cd "$current"
  # echo "*************************************************************************************************"
   #echo -e "\e[92m[~] Scanning for CRLF injection.."
   #echo -e "\e[92m[~] CRLF-Injection-Scanner will be in action.."
   #echo "*************************************************************************************************"
   #cp "$domain"_unique.txt /root/scripts/bounty/CRLF-Injection-Scanner/
   #cd /root/scripts/bounty/CRLF-Injection-Scanner/
   #python crlf_scan.py -i "$domain"_unique.txt -o "$domain"_crlf.txt
   #echo "*************************************************************************************************"
   #if [ -e "$domain"_crlf.txt ]
   #then
	#cat "$domain"_crlf.txt
	#cp "$domain"_crlf.txt "$current"/"$domain"/"$subdirectory"/fuzzing/
	#rm "$domain"_crlf.txt
 #  else
#	echo "********************************************************************************************"
#	echo -e "\e[31m[~] No crlf found.."
#	echo "********************************************************************************************"
 #  fi
  # rm "$domain"_unique.txt
   #cors
#}


s3scan()
{
   bucket=`echo "$domain" | cut -d "." -f 1`
   echo "**************************************************************************************************"
   echo -e "\e[92m[~] Scanning for s3 bucket.."
   echo -e "\e[92m[~] S3Scanner will be in action.."
   echo "**************************************************************************************************"
   cd "$current"
#   cp "$domain"_unique.txt /root/scripts/bounty/S3Scanner/
 #  cd /root/scripts/bounty/S3Scanner/
  # sleep 3
   #python s3scanner.py --out-file "$domain"_s3scan.txt "$domain"_unique.txt
#   if [ -s "$domain"_s3scan.txt ]
 #  then
#	echo -e "\e[92m[~] Found something interesting.."
#	echo "**********************************************************************************"
#	cat "$domain"_s3scan.txt
#	echo "**********************************************************************************"
 #  else
#	echo "**********************************************************************************"
#	echo -e "\e[92m[~] File is empty no s3 buckets found.."
#	echo "**********************************************************************************"
 #  fi
  # cp "$domain"_s3scan.txt /"$current"/"$domain"/"$subdirectory"/subdomains/
   #rm "$domain"_s3scan.txt "$domain"_unique.txt
   echo "***************************************************************************************"
   echo -e "\e[92m[~] Cloud_enum will start.."
   cd /root/scripts/bounty/cloud_enum/
   ./cloud_enum.py -t 20 -m all.txt -l "$domain"_s3_bucket.txt -k "$bucket" --disable-azure --disable-gcp
   cat "$domain"_s3_bucket.txt | grep "OPEN S3 BUCKET:"
   cp "$domain"_s3_bucket.txt "$current"/"$domain"/"$subdirectory"/subdomains/
   rm "$domain"_s3_bucket.txt
   echo "***************************************************************************************"
#   echo -e "\e[92m[~] Gogetbucket will start.."
   echo "***************************************************************************************"
#   cd "$current"
 #  cp "$domain"_unique.txt /root/go/src/github.com/glen-mac/goGetBucket/
  # cd /root/go/src/github.com/glen-mac/goGetBucket/
  # ./main -m lists/all.txt -d "$bucket" -o "$domain"_bucket.txt -i "$domain"_unique.txt
  # cp "$domain"_bucket.txt /"$current"/"$domain"/"$subdirectory"/subdomains/
  # cat "$domain"_bucket.txt | grep true
  # rm "$domain"_bucket.txt
   echo "***************************************************************************************"
   echo -e "\e[92m[~] Bucket finder will start.."
   echo "***************************************************************************************"
   cd "$current"
   cp "$domain"_unique.txt ../bucket_finder/
   cd /root/scripts/bounty/bucket_finder/
   ./bucket_finder.rb -v "$domain"_unique.txt -l bucket_finder_op.txt
   cp bucket_finder_op.txt "$current"/"$domain"/"$subdirectory"/subdomains/
   rm bucket_finder_op.txt "$domain"_unique.txt
   linkfinder

}


#dirbruteforce()
#{
 #  cd "$current"
  # echo "***************************************************************************************************"
   #echo -e "\e[92m[~] Dirbruteforce will start.."
   #echo -e "\e[92m[~] Gobuster will be in action.."
   #echo "***************************************************************************************************"
   #touch "$domain"_gobuster.txt
   #for Host in `cat "$domain"_unique.txt`
   #do
#	echo "**********************************************************************************************" >> "$domain"_gobuster.txt
#	echo 						"$Host"					     >> "$domain"_gobuster.txt
#	echo "**********************************************************************************************" >> "$domain"_gobuster.txt
#	gobuster dir -u "$Host" -t 300 -v --wildcard -s 200,201 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt >> "$domain"_gobuster.txt
#	echo "**********************************************************************************************"
 #  done	

  # echo "Potential Directories found .."
   #cat "$domain"_gobuster.txt | grep "(Status: 200)"
  # cp "$domain"_gobuster.txt ./"$domain"/"$subdirectory"/fuzzing/
   #rm "$domain"_gobuster.txt
   #s3scan
#}


#vhostscan()
#{
 #  service apache2 start
  # cd "$current"
   #cp "$domain"_unique.txt /root/scripts/bounty/virtual-host-discovery/
   #cd /root/scripts/bounty/virtual-host-discovery
   #echo "******************************************************************************"
   #echo -e "\e[92m[~] Let's scan for some virtual host.."
   #echo -e "\e[92m[~] Virtual-Host-Scanner will be in action..."
   #echo "******************************************************************************"
   #sleep 3
   #for Host in `cat "$domain"_unique.txt`
   #do
#	ruby scan.rb --ip="$IP" --host="$Host" --ignore-http-codes=400,404,302,403 >> "$domain"_vhost.txt
#	echo "*************************************************************************" >> "$domain"_vhost.txt
 #  done
  # cat "$domain"_vhost.txt
   #cp "$domain"_vhost.txt "$current"/"$domain"/"$subdirectory"/fuzzing/
   #rm "$domain"_vhost.txt
   #echo -e "\e[92m[~] VHost scan completed.."
   #echo "******************************************************************************"
   #dirbruteforce
#}


portscan()
{
   echo "********************************************************************************"
   echo -e "\e[92m[~] Masscan will start in some time.."
   sleep 3
   iptables -A INPUT -p tcp --dport 61000 -j DROP    #some problem with masscan
   masscan -iL "$domain"_sorted_ip.txt -p0-65535 --rate 100000 --banners --source-port 61000 -v -oG "$domain"_masscan.txt
   cp "$domain"_masscan.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/subdomains/
   rm "$domain"_masscan.txt
   echo -e "\e[31m[~] Masscan completed.."
   echo "********************************************************************************"
#   echo -e "\e[92m[~] Nmap will start to grab banner.."
   echo "********************************************************************************"
   sleep 3
#   touch "$domain"_banner.txt
#   for ip in `cat "$domain"_sorted_ip.txt`
#   do
#	nmap -sV --script=banner "$ip" | sed '$d' | sed '$d' >> "$domain"_banner.txt
#	echo "**************************************************************************************************" >> "$domain"_banner.txt
#	cat "$domain"_banner.txt
#   done
#   echo -e "\e[92m[~] NSE banner grabbing completed.."
   echo "**********************************************************************************"
   cd /root/scripts/bounty/Myrecon/
#   cp "$domain"_banner.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/subdomains/
#   rm "$domain"_banner.txt
   cp "$domain"_sorted_ip.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/subdomains/
   rm "$domain"_sorted_ip.txt
   s3scan
}


ipresolve()
{
   cd "$current"
   echo "***********************************************************************************"
   echo -e "\e[92m[~] Now resolving ip for port scanning"
   sleep 3
   touch "$domain"_ip.txt
   cp "$domain"_unique.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/fuzzing/
   for ip in `cat "$domain"_unique.txt`
   do
	host "$ip" | cut -d " " -f 4 | sed 's/alias//g' | sed 's/CNAME//g' | sed 's/address//g' | sed 's/found://g' | sed 's/out;//g' | sed 's/handled//g' | sed '/^$/d' >> "$domain"_ip.txt
	cat "$domain"_ip.txt
   done
   echo "***********************************************************************************"
   echo -e "\e[92m[~] Sorting file for unqiue ip"
   cp "$current"/"$domain"/"$subdirectory"/subdomains/knock_ip.txt "$current"
   cp "$current"/"$domain"/"$subdirectory"/subdomains/massdns_ip.txt "$current"
   cat knock_ip.txt >> "$domain"_ip.txt
   cat massdns_ip.txt >> "$domain"_ip.txt
   cat "$domain"_ip.txt | sort -u > "$domain"_sorted_ip.txt
   cp "$domain"_sorted_ip.txt ./"$domain"/"$subdirectory"/subdomains/
   rm "$domain"_ip.txt knock_ip.txt massdns_ip.txt 
   echo -e "\e[92m[~] File sorted successfully and passing to port scanning"
   echo "***********************************************************************************"
   sleep 3
}


subdomain()
{
   echo ""
   echo -e "\e[31m[~] Sublist3r will start in 2 seconds.."
   sleep 2
   clear
   python3 /root/scripts/bounty/Sublist3r/sublist3r.py -d "$domain" -t 50 -o ./"$domain"/"$subdirectory"/subdomains/sublist3r.txt -v
   echo ""
   echo -e "\e[92m[~] Sublist3r scan completed.."
   echo "*****************************************************************************************"
   echo -e "\e[93m[~] Amass scan will start in 2 seconds"
   sleep 2
   echo -e "\e[31m[~] Amass scan started"
   echo "*****************************************************************************************"
   amass enum -passive -d "$domain" -o ./"$domain"/"$subdirectory"/subdomains/amass_result.txt
   echo -e "\e[92m[~] Amass scan completed"
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] File saved as amass_result.txt"
   echo "*****************************************************************************************"
   echo -e "\e[93m[~] findomain and subfinder in work.. scan will start in 3 seconds.."
   sleep 3
   subfinder -d "$domain" -t 30 -o ./"$domain"/"$subdirectory"/subdomains/subfinder_result.txt
   findomain -t "$domain" -o
   cp "$domain".txt ./"$domain"/"$subdirectory"/subdomains/findomain_result.txt
   rm "$domain".txt
   echo -e "\e[92m[~] findomain scan completed"
   echo -e "\e[92m[~] File saved as $domain.txt"
   echo "*****************************************************************************************"
   echo -e "\e[93m[~] Knock will start scanning in 5 seconds"
   sleep 5
   knockpy -c "$domain"
   echo -e "\e[92m[~] Filtering the output..."
   cat *.csv | cut -d "," -f 4 > ./"$domain"/"$subdirectory"/subdomains/knock_domains.txt  #taking only domain name
   cat *.csv | cut -d "," -f 1 > ./"$domain"/"$subdirectory"/subdomains/knock_ip.txt   #taking only ip's
   echo -e "\e[92m[~] Knock scan completed..."
   echo -e "\e[92m[~] File saved as knock_domains"
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] Compiling unique results for massdns to scan"
   cat ./"$domain"/"$subdirectory"/subdomains/sublist3r.txt > ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/amass_result.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/findomain_result.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/knock_domains.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/subfinder_result.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/"$domain".txt | sort -u > ./"$domain"/"$subdirectory"/subdomains/"$domain"_Bunique.txt
   if [ -e ./"$domain"/"$subdirectory"/subdomains/"$domain"_Bunique.txt ]
   then
	echo -e "\e[92m[~] File compiled,sorted successfully"
   else
	echo -e "\e[31m[~] File not found..can't proceed"
	exit 1
   fi
   echo "*****************************************************************************************"
   sleep 5
   cp ./"$domain"/"$subdirectory"/subdomains/"$domain"_Bunique.txt "$current"
#   echo -e "\e[92m[~] passing file to massdns for active DNS resolution"
   echo "*****************************************************************************************"
#   $massdns -r /root/scripts/bounty/massdns/lists/resolvers.txt "$domain"_unique.txt -t A -o S -w ./"$domain"/"$subdirectory"/subdomains/massdns.txt
#   cat ./"$domain"/"$subdirectory"/subdomains/massdns.txt | cut -d " " -f 3 > ./"$domain"/"$subdirectory"/subdomains/massdns_ip.txt
 #  cat ./"$domain"/"$subdirectory"/subdomains/massdns.txt | cut -d " " -f 1 > ./"$domain"/"$subdirectory"/subdomains/massdns_domain.txt
 #  $altdns -i ./"$domain"/"$subdirectory"/subdomains/massdns_domain.txt -t 50 -w /root/scripts/bounty/altdns/words.txt -o ./"$domain"/"$subdirectory"/subdomains/altdns.txt
 #  cp ./"$domain"/"$subdirectory"/subdomains/altdns.txt "$current"
 #  $massdns -r /root/scripts/bounty/massdns/lists/resolvers.txt altdns.txt -t A -o S -w ./"$domain"/"$subdirectory"/subdomains/massdns_altdns.txt
 #  echo -e "\e[92m[~] Compiling results in File"
 #  echo "*****************************************************************************************"
 #  cat ./"$domain"/"$subdirectory"/subdomains/massdns_altdns.txt | cut -d " " -f 1 >> ./"$domain"/"$subdirectory"/subdomains/"$domain"_mix.txt
 #  cat ./"$domain"/"$subdirectory"/subdomains/massdns_altdns.txt | cut -d " " -f 3 >> ./"$domain"/"$subdirectory"/subdomains/massdns_ip.txt
 #  rm *.csv
  # echo -e "\e[92m[~] Massdns and altdns scan completed file saved.."
  # echo "*****************************************************************************************"
   rm -rf amass_output altdns.txt
#   cp ./"$domain"/"$subdirectory"/subdomains/"$domain"_mix.txt "$current"
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] Checking whether host is alive or not.."
#   cp "$domain"_mix.txt "$domain"_unique.txt
#   rm "$domain"_unique.txt
 #  for host in `cat "$domain"_unique.txt`
  # do
#	if [ $(curl -I "$host" --write-out %{http_code} -m 5 -s --output /dev/null) == 000 ]
#		then
 #  			sed -i "/${host}/d" "$domain"_unique.txt
#	fi
 #  done
   echo -e "\e[92m[~] Recce will be in action.."
   cd "$current"
   cp "$domain"_Bunique.txt ../recce/
   cd /root/scripts/bounty/recce/
   python3 recce.py -f "$domain"_Bunique.txt -t 20 -o "$domain"_unique.txt
   cp "$domain"_unique.txt "$current"
   echo -e "\e[92m[~] All Host checked.."
   echo -e "\e[92m[~] Total online.."
   cat "$domain"_unique.txt | wc -l
   echo "******************************************************************************************"
   cp "$domain"_unique.txt "$current"/"$domain"/"$subdirectory"/subdomains/
   echo "******************************************************************************************"
   rm "$domain"_unique.txt "$domain"_Bunique.txt
   cd "$current"/"$domain"/"$subdirectory"/subdomains
   cp "$domain"_unique.txt aquatone/
   rm -rf amass_output sublist3r.txt amass_result.txt findomain_result.txt knock_domain.txt massdns.txt massdns_domain.txt altdns.txt massdns_altdns.txt subfinder_result.txt
   cd aquatone/
   echo -e "\e[92m[~] Passing file to aquatone"
   echo "*****************************************************************************************"
   sleep 3
   sed -i 's/^/https:\/\//' "$domain"_unique.txt
   cat "$domain"_unique.txt | aquatone -debug
   rm -rf "$domain"_unique.txt headers html aquatone_urls.txt
   cd "$current"
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] Script Now scan for subdomain takeover"
   echo "*****************************************************************************************"
   sleep 2
   cp "$domain"_unique.txt /root/go/src/github.com/haccer/subjack/
   cd /root/go/src/github.com/haccer/subjack
   echo -e "\e[92m[~] Directory changed.."
   echo -e "\e[92m[~] Subjack is in action.."
   echo "*****************************************************************************************"
   sleep 2
   ./main -c fingerprints.json -t 50 -timeout 20 -v -w "$domain"_unique.txt -o subjack_result.txt
   cp subjack_result.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/subdomains/
   rm subjack_result.txt "$domain"_unique.txt
   echo -e "\e[92m[~] subjack completed his task.."
   echo "*****************************************************************************************"
   cd -
   cp "$domain"_unique.txt /root/go/src/github.com/Ice3man543/SubOver/
   cd /root/go/src/github.com/Ice3man543/SubOver/
   echo -e "\e[92m[~] Directory changed..."
   echo -e "\e[92m[~] Subover is in action..."
   sleep 2
   ./subover -l "$domain"_unique.txt -t 100 -timeout 30 -v -o "$domain"_subover.txt
   cp "$domain"_subover.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/subdomains/
   rm "$domain"_subover.txt "$domain"_unique.txt
   echo -e "\e[92m[~] subover completed his task.."
   echo "*****************************************************************************************"
   cd "$current"
   cp "$domain"_unique.txt /root/go/src/github.com/anshumanbh/tko-subs/
   cd /root/go/src/github.com/anshumanbh/tko-subs/
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] Directory changed.."
   echo -e "\e[92m[~] tko-subs is in action.."
   echo "*****************************************************************************************"
   sleep 1
   ./tko-subs -domains "$domain"_unique.txt -data providers-data.csv -threads 100
   echo "*****************************************************************************************"
   cp output.csv /"$current"/"$domain"/"$subdirectory"/fuzzing/"$domain"_tko-subs.csv
   cd /"$current"/"$domain"/"$subdirectory"/fuzzing/
   count=`wc -l "$domain"_tko-subs.csv | cut -d " " -f 1`
   if [ "$count" == 1 ]
   then
	echo -e "\e[31m[~] No takeovers found.."
	echo "************************************************************************************"
   else
	echo -e "\e[92m[~] Takeovers found check manually.."
	cat "$domain"_tko-subs.csv
	echo "************************************************************************************"
   fi
}

helpFunction()
{
   echo ""
   echo -e "\e[91m[~] Usage: $0 -d example.com "
   echo -e "\t-d domain name for the recon"
   exit 1 # Exit script after printing help
}

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
   echo -e "\e[91m[~] Target already scanned"
else
   mkdir ./"$domain"
   mkdir ./"$domain"/"$subdirectory"
   mkdir ./"$domain"/"$subdirectory"/subdomains
   mkdir ./"$domain"/"$subdirectory"/subdomains/aquatone
   mkdir ./"$domain"/"$subdirectory"/fuzzing/
fi

if [ -z "$domain" ]
then
   echo -e "\e[91m[~] Pass the domain name";
   helpFunction
else
   subdomain
   ipresolve
   portscan
fi
