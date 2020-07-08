#!/bin/bash
#clear
banner=`figlet -f slant myrecon`    #without banner there is no script
echo -e "\e[93;1m${banner}" 
echo -e "			\e[31;1m A script by Shubham Chaskar"

echo " "
current=`pwd`
#massdns=/root/scripts/bounty/massdns/bin/massdns
#altdns=/root/scripts/bounty/altdns/altdns.py
#ifconfig wlan0 down
#IP=`ifconfig wlan1 | grep "inet " | cut -d ' ' -f 10`


gitrecon()
{
   cd "$current"/"$domain"/"$subdirectory"/subdomains/
   cd ../github_recon
   echo "***************************************************************************************"
   echo -e "\e[92m[~] gitgraber will be in action.."
   cd /root/scripts/bounty/gitGraber/
   python3 gitGraber.py -k ./wordlists/all_keywords.txt -q "$domain" -s | tee -a "$current"/"$domain"/"$subdirectory"/github_recon/gitgraber_result.txt
   cd "$current"
 #  ./main -save "$domain"_gitrob -threads 100 "$git"
 #  cp "$domain"_gitrob "$current"/"$domain"/"$subdirectory"/
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
vulnscan()
{
  cd "$current"/"$domain"/"$subdirectory"/subdomains/
#Jaeles Scanner
#  mkdir ../vulns/jaeles_result
 # jaeles scan -U "$domain"_unique.txt -c 150 -L 2 -o ../vulns/jaeles_result -s "/root/.jaeles/base-signatures/all/.*"
#Nuclei Scanner
  nuclei -c 200 -l "$domain"_unique.txt -silent -t all/ -o ../vulns/nuclei_result.txt
#XSS parameter scanning
  cd ../URLs/
  cat clean_url.txt | kxss | tee -a ../vulns/xss_reflection_kxss.txt
  cat spider_clean_1.txt | kxss | tee -a ../vulns/xss_reflection_kxss.txt
  cat spider_clean_2.txt | kxss | tee -a ../vulns/xss_reflection_kxss.txt
  cd ../vulns/
  if [ -s xss_reflection_kxss.txt ]
  then
	cat xss_reflection_kxss.txt | cut -d " " -f 9 > dalfox_input.txt
	cat dalfox_input.txt | dalfox pipe -blind "$blind" -o ../vulns/dalfox_result.txt -w 30
  else
	echo -e "\e[92m[~] No reflections has been found.."
  fi

#Hidden parameter discovery
  cp ../subdomains/"$domain"_unique.txt /root/scripts/bounty/Arjun/
  cd /root/scripts/bounty/Arjun/
  python3 arjun.py --urls "$domain"_unique.txt --get -t 50 -o arjun_result.json
  mv arjun_result.json "$current"/"$domain"/"$subdirectory"/URLs/

#gf-patterns and separate files with repect to vulnerabilities
#SSRF
  ss="$ssrf"            #ssrftest.com or ngrok or burp private collaborator
  cd "$current"/"$domain"/"$subdirectory"/URLs/
  cat clean_url.txt spider_clean_1.txt spider_clean_2.txt | grep "=" | gf ssrf | tee -a ../vulns/possible_ssrf.txt
  cat ../vulns/possible_ssrf.txt | sed "s|$|\&dest=$ss\&redirect=$ss\&uri=$ss\&path=$ss\&continue=$ss\&url=$ss\&window=$ss\&next=$ss\&data=$ss\&reference=$ss\&site=$ss\&html=$ss\&val=$ss\&validate=$ss\&domain=$ss\&callback=$ss\&return=$ss\&page=$ss\&feed=$ss\&host=$ss&\port=$ss\&to=$ss\&out=$ss\&view=$ss\&dir=$ss\&show=$ss\&navigation=$ss\&open=$ss|g" | tee -a ../vulns/possible_ssrf_2.txt
  ffuf -w ../vulns/possible_ssrf_2.txt -u FUZZ -t 100 -of html -o ../vulns/ssrf_2_result_ffuf.html
#IDOR
  cat clean_url.txt spider_clean_1.txt spider_clean_2.txt | grep "=" | gf idor | tee -a ../vulns/possible_idor.txt
#SSTI
  cat clean_url.txt spider_clean_1.txt spider_clean_2.txt | grep "=" | gf ssti | tee -a ../vulns/possible_ssti.txt
  cd ../vulns/
  ssti=200
  t=`cat possible_ssti.txt | wc -l`
  if [ "$ssti" -gt "$t" ]
  then
  	for line in `cat possible_ssti.txt`;
  	do
		echo $line && python /root/scripts/bounty/tplmap/tplmap.py -u $line | tee -a ssti_tpl_result.txt;
  	done
  fi
  cd ../URLs/
#open-redirect
  cat clean_url.txt spider_clean_1.txt spider_clean_2.txt | grep "=" | gf redirect | tee -a ../vulns/possible_OR.txt
  cd ../vulns/
  if [ -s possible_OR.txt ]
  then
	echo -e "\e[92m[~] Checking for openredirect.."
	python3 /root/scripts/bounty/pentest-tools/openredirect.py -u possible_OR.txt -p /root/scripts/bounty/Myrecon/OR_payloads.txt -t 40
  else
	echo -e "\e[92m[~] No patterns found.."
  fi
#LFI
  cd ../URLs/
  cat clean_url.txt spider_clean_1.txt spider_clean_2.txt | grep "=" | gf lfi | tee -a ../vulns/possible_lfi.txt
  cd ../vulns/
  if [ -s possible_lfi.txt ]
  then
	echo -e "\e[92m[~] Checking for LFI.."
	python3 /root/scripts/bounty/pentest-tools/lfi.py -u possible_lfi.txt -p /root/scripts/bounty/pentest-tools/LFI-Jhaddix.txt -t 40
	cp -r crlf/ lfi
	rm -r crlf
  else
	echo -e "\e[92m[~] No patterns found.."
  fi
#RCE
  cd ../URLs/
  cat clean_url.txt spider_clean_1.txt spider_clean_2.txt | grep "=" | gf rce | tee -a ../vulns/possible_rce.txt
#SQLi
  cat clean_url.txt spider_clean_1.txt spider_clean_2.txt | grep "=" | gf sqli | tee -a ../vulns/possible_sqli.txt
  cd ../vulns/
  mkdir sql_result
  mkdir POC
  sql=200
  b=`cat possible_sqli.txt | wc -l`
  if [ -s possible_sqli.txt ]
  then
        echo -e "\e[92m[~] File found with content.."
	if [ "$sql" -gt "$b" ]
	then
		cp possible_sqli.txt /root/scripts/bounty/sqlmap-dev/ && python3 /root/scripts/bounty/sqlmap-dev/sqlmap.py -m possible_sqli.txt --threads 10 --batch --random-agent --level 3 --output-dir="$current"/"$domain"/"$subdirectory"/vulns/sql_result/
	else
		echo -e "\e[92m[~] File with more than $a line will not be scanned.."
	fi
  else
        echo -e "\e[92m[~] No patterns found for sqli.."
  fi
#Jaeles Scanner
  mkdir ../vulns/jaeles_result
  cd "$current"/"$domain"/"$subdirectory"/subdomains/
  jaeles scan -U "$domain"_unique.txt -c 150 -L 2 -o ../vulns/jaeles_result -s "/root/.jaeles/base-signatures/all/.*"
  cd ../URLs/
  cat clean_url.txt | grep "=" | hakcheckurl | grep "200" | cut -d " " -f 2 | tee -a smuggle_input.txt
  cp smuggle_input.txt /root/scripts/bounty/smuggler/
  cd /root/scripts/bounty/smuggler/
  cat smuggle_input.txt | python3 smuggler.py -x -q -l smuggler_output_defparam.txt
  mv smuggler_output_defparam.txt "$current"/"$domain"/"$subdirectory"/vulns/
  cp -r payloads/ "$current"/"$domain"/"$subdirectory"/vulns/POC/
  cd payloads/
  find . ! -name 'README.md' -type f -exec rm -f {} +
  find . ! -name 'README.md' -type d -exec rm -r {} +
  cd ../../pentest-tools/
  python3 smuggler.py -u ../smuggler/smuggle_input.txt -t 40
  mv smuggler/ "$current"/"$domain"/"$subdirectory"/vulns/
  gitrecon
}

spider()
{
# Crawl all subdomains and filter the result
   cd "$current"/"$domain"/"$subdirectory"/subdomains/
   gospider -S "$domain"_unique.txt -o ../URLs/crawl_data/ -t 30 -c 10 -r -a -d 3
   cd ../URLs/crawl_data/
   cat * | grep -v -E "(.jpg|.JPG|.png|.svg|.gif|.ttf|.css|.js|.pdf|.mp4|.mp3|.woff|.eot|.jpeg|.exe|.woff2)" | grep "=" | grep "code-200" | cut -d " " -f 5 | qsreplace -a | tee -a ../spider_clean_1.txt
   cat * | grep -v -E "(.jpg|.JPG|.png|.svg|.gif|.ttf|.css|.js|.pdf|.mp4|.mp3|.woff|.eot|.jpeg|.exe|.woff2)" | grep "=" | grep "other-sources" | cut -d "-" -f 3 | tr -d " " | qsreplace -a | tee -a ../spider_clean_2.txt
   cd ../
   if [ -z "$module" ]
   then
	vulnscan
   else
        echo -e "\e[92m[~] $module completed results can be found in $current/$domain/$subdirectory"
        echo "************************************************************************************"
        exit 0
   fi
}

wayback()
{
   cd "$current"/"$domain"/"$subdirectory"/subdomains/
   echo "***********************************************************************************************"
   echo -e "\e[92m[~] Going back in time to search some endpoints.."
   echo -e "\e[92m[~] Waybackurl will be in action.."
   echo "***********************************************************************************************"
   cat subjack_input.txt | waybackurls -no-subs | tee -a ../URLs/wayback.txt
   echo "***********************************************************************************************"
   echo -e "\e[92m[~] Getallurls will be in action.."
   echo "***********************************************************************************************"
   cat subjack_input.txt | gau | tee -a ../URLs/gau.txt
   cd ../URLs/
   cat wayback.txt gau.txt | grep "=" | grep -v -E "(.jpg|.JPG|.png|.svg|.gif|.ttf|.css|.js|.pdf|.mp4|.mp3|.woff|.eot|.jpeg|.exe|.woff2)" | qsreplace -a | tee -a clean_url.txt
   if [ -z "$module" ]
   then
	spider
   else
        echo -e "\e[92m[~] $module completed results can be found in $current/$domain/$subdirectory"
        echo "************************************************************************************"
        exit 0
   fi
}



linkfinder()
{
   echo "***********************************************************************************************"
   echo -e "\e[92m[~] Finding JS files and endpoints.."
   echo -e "\e[92m[~] Linkfinder will be in action.."
   echo "***********************************************************************************************"
   cp "$domain"_unique.txt /root/scripts/bounty/LinkFinder/
   cd /root/scripts/bounty/LinkFinder/
   touch "$domain"_js_endpoints.txt
#   sed -i 's/^/https:\/\//' "$domain"_unique.txt
   for host in `cat "$domain"_unique.txt`
   do
	echo "******************************************************************************************" >> "$domain"_js_endpoints.txt
	echo 					"$host"						>> "$domain"_js_endpoints.txt
	echo "Analysing $host"
	echo "******************************************************************************************" >> "$domain"_js_endpoints.txt
	python3 linkfinder.py -i "$host" -d -o cli >> "$domain"_js_endpoints.txt
   done
   echo -e "\e[92m[~] Found some endpoints.."
   mv "$domain"_js_endpoints.txt "$current"/"$domain"/"$subdirectory"/URLs/
#   cat "$domain"_js_endpoints.txt
   rm "$domain"_unique.txt
 #  filefuzz
   if [ -z "$module" ]
   then
	wayback
   else
        echo -e "\e[92m[~] $module completed results can be found in $current/$domain/$subdirectory"
        echo "************************************************************************************"
        exit 0
   fi
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


crlf()
{
   cd "$current"/"$domain"/"$subdirectory"/subdomains/
   echo "*************************************************************************************************"
   echo -e "\e[92m[~] Scanning for CRLF injection.."
   echo -e "\e[92m[~] CRLF-Injection-Scanner will be in action.."
   echo "*************************************************************************************************"
   cat subjack_input.txt | interlace -threads 10 -c "crlf scan -u _target_" -v | tee -a ../vulns/crlf_result.txt
   echo "*************************************************************************************************"
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
   if [ -z "$module" ]
   then
	linkfinder
   else
        echo -e "\e[92m[~] $module completed results can be found in $current/$domain/$subdirectory"
        echo "************************************************************************************"
        exit 0
   fi
}


s3scan()
{
   bucket=`echo "$domain" | cut -d "." -f 1`
   echo "**************************************************************************************************"
   #echo -e "\e[92m[~] Scanning for s3 bucket.."
   #echo -e "\e[92m[~] S3Scanner will be in action.."
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
   python3 cloud_enum.py -t 20 -m all.txt -l "$domain"_s3_bucket.txt -k "$bucket" --disable-azure --disable-gcp
   python3 cloud_enum.py -t 20 -m all.txt -l "$domain"_gcp_bucket.txt -k "$bucket" --disable-azure --disable-aws
   python3 cloud_enum.py -t 20 -m all.txt -l "$domain"_azure.txt -k "$bucket" --disable-aws --disable-gcp
   cp "$domain"_s3_bucket.txt "$domain"_gcp_bucket.txt "$domain"_azure.txt "$current"/"$domain"/"$subdirectory"/buckets/
   rm "$domain"_s3_bucket.txt "$domain"_gcp_bucket.txt "$domain"_azure.txt
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
  # echo "***************************************************************************************"
  # echo -e "\e[92m[~] Bucket finder will start.."
  # echo "***************************************************************************************"
  # cd "$current"
  # cp "$domain"_unique.txt ../bucket_finder/
  # cd /root/scripts/bounty/bucket_finder/
  # ./bucket_finder.rb -v "$domain"_unique.txt -l bucket_finder_op.txt
  #cp bucket_finder_op.txt "$current"/"$domain"/"$subdirectory"/subdomains/
  # rm bucket_finder_op.txt "$domain"_unique.txt
  if [ -z "$module" ]
  then
	crlf
  else
        echo -e "\e[92m[~] $module completed results can be found in $current/$domain/$subdirectory"
        echo "************************************************************************************"
        exit 0
   fi
}


dirbruteforce()
{
   cd "$current"
   echo "***************************************************************************************************"
   echo -e "\e[92m[~] Dirbruteforce will start.."
   echo -e "\e[92m[~] FFUF will be in action.."
   echo "***************************************************************************************************"
   cd ./"$domain"/"$subdirectory"/subdomains/
   ffuf -t 300 -c -sf -fc '404,429,501,502,503,500,301,302' -of html -o ../directory/ffuf.html -u HOST/FUZZ -w "$domain"_unique.txt:HOST -w "$wordlist":FUZZ -mode clusterbomb
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
   if [ -z "$module" ]
   then
	s3scan
   else
        echo -e "\e[92m[~] $module completed results can be found in $current/$domain/$subdirectory"
        echo "************************************************************************************"
        exit 0
   fi
}



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
   echo -e "\e[92m[~] naabu will start in some time.."
   sleep 3
#   iptables -A INPUT -p tcp --dport 61000 -j DROP    #some problem with masscan
#   masscan -iL "$domain"_sorted_ip.txt -p0-65535 --rate 100000 --banners --source-port 61000 -v -oG "$domain"_masscan.txt
#   cp "$domain"_masscan.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/subdomains/
#   rm "$domain"_masscan.txt
   cd /"$current"/"$domain"/"$subdirectory"/subdomains/
   naabu -hL subjack_input.txt -t 20 -verify -retries 4 -timeout 1000 -ports full -silent -o ../portscan/naabu_output.txt
   echo -e "\e[31m[~] Naabu completed.."
   echo "********************************************************************************"
#   echo -e "\e[92m[~] Nmap will start to grab banner.."
   echo "********************************************************************************"
   sleep 2
   cat ../portscan/naabu_output.txt | bash "$current"/nmap.sh
#   touch "$domain"_banner.txt
#   for ip in `cat "$domain"_sorted_ip.txt`
#   do
#	nmap -sV --script=banner "$ip" | sed '$d' | sed '$d' >> "$domain"_banner.txt
#	echo "**************************************************************************************************" >> "$domain"_banner.txt
#	cat "$domain"_banner.txt
#   done
   echo -e "\e[92m[~] NMAP service detection completed.."
   echo "**********************************************************************************"
   mv naabu_output_ports.txt ../portscan/
   mv naabu_output_targets.txt ../portscan/
   if [ -z "$module" ]
   then
	dirbruteforce
   else
	echo -e "\e[92m[~] $module completed results can be found in $current/$domain/$subdirectory"
        echo "************************************************************************************"
        exit 0
   fi
}


#ipresolve()
#{
 #  cd "$current"
#   echo "***********************************************************************************"
 #  echo -e "\e[92m[~] Now resolving ip for port scanning"
  # sleep 1
  # touch "$domain"_ip.txt
  # cp "$domain"_unique.txt /root/scripts/bounty/Myrecon/"$domain"/"$subdirectory"/fuzzing/
  # for ip in `cat "$domain"_unique.txt`
  # do
#	host "$ip" | cut -d " " -f 4 | sed 's/alias//g' | sed 's/CNAME//g' | sed 's/address//g' | sed 's/found://g' | sed 's/out;//g' | sed 's/handled//g' | sed '/^$/d' >> "$domain"_ip.txt
#	cat "$domain"_ip.txt
 #  done
  # echo "***********************************************************************************"
  # echo -e "\e[92m[~] Sorting file for unqiue ip"
  # cp "$current"/"$domain"/"$subdirectory"/subdomains/knock_ip.txt "$current"
  # cp "$current"/"$domain"/"$subdirectory"/subdomains/massdns_ip.txt "$current"
  # cat knock_ip.txt >> "$domain"_ip.txt
  # cat massdns_ip.txt >> "$domain"_ip.txt
  # cat "$domain"_ip.txt | sort -u > "$domain"_sorted_ip.txt
  # cp "$domain"_sorted_ip.txt ./"$domain"/"$subdirectory"/subdomains/
  # rm "$domain"_ip.txt knock_ip.txt massdns_ip.txt 
  # echo -e "\e[92m[~] File sorted successfully and passing to port scanning"
  # echo "***********************************************************************************"
  # sleep 3
#}

subdomain()
{
   cd "$current"
   echo ""
   echo -e "\e[31m[~] assetfinder will start in a second.."
   sleep 1
   clear
   cd ./"$domain"/"$subdirectory"/subdomains/
   assetfinder -subs-only "$domain" | tee assetfinder_result.txt
   echo ""
   echo -e "\e[92m[~] assetfinder scan completed.."
   echo "*****************************************************************************************"
   echo -e "\e[93m[~] Amass scan will start in a second.."
   sleep 1
   echo -e "\e[31m[~] Amass scan started"
   echo "*****************************************************************************************"
   amass enum -passive -d "$domain" -o amass_result.txt
   echo -e "\e[92m[~] Amass scan completed"
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] File saved as amass_result.txt"
   echo "*****************************************************************************************"
   echo -e "\e[93m[~] findomain and subfinder in work.. scan will start in a second.."
   sleep 1
   subfinder -d "$domain" -t 30 -o subfinder_result.txt
   findomain -t "$domain" -o
   cp "$domain".txt findomain_result.txt
   rm "$domain".txt
   echo -e "\e[92m[~] findomain scan completed"
   echo -e "\e[93m[~] finding subdomains from github.."
   cd /root/scripts/bounty/github-search/
   python3 github-subdomains.py -t "3eaa91453b38ef456900f31f91cb4024d65dc5fb" -d "$domain" | tee -a "$current"/"$domain"/"$subdirectory"/subdomains/github_domains.txt
   echo "*****************************************************************************************"
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] Compiling unique results to scan"
   cd "$current"
   cat ./"$domain"/"$subdirectory"/subdomains/assetfinder_result.txt > ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/amass_result.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/findomain_result.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/subfinder_result.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/github_domains.txt >> ./"$domain"/"$subdirectory"/subdomains/"$domain".txt
   cat ./"$domain"/"$subdirectory"/subdomains/"$domain".txt | sort -u > ./"$domain"/"$subdirectory"/subdomains/"$domain"_Bunique.txt
   if [ -e ./"$domain"/"$subdirectory"/subdomains/"$domain"_Bunique.txt ]
   then
	echo -e "\e[92m[~] File compiled,sorted successfully"
   else
	echo -e "\e[31m[~] File not found..can't proceed"
	exit 1
   fi
   echo "*****************************************************************************************"
   sleep 2
#   cp ./"$domain"/"$subdirectory"/subdomains/"$domain"_Bunique.txt "$current"
#   echo -e "\e[92m[~] passing file to massdns for active DNS resolution"
#   echo "*****************************************************************************************"
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
   echo -e "\e[92m[~] httprobe will be in action.."
   cd "$current"
   cp ./"$domain"/"$subdirectory"/subdomains/"$domain"_Bunique.txt ./"$domain"/"$subdirectory"/probing/
   cd ./"$domain"/"$subdirectory"/probing/
   cat "$domain"_Bunique.txt | httprobe -c 150 -t 20000 | tee "$domain"_unique.txt
   cp "$domain"_unique.txt ../subdomains/
   echo -e "\e[92m[~] All Host checked.."
 #  echo -e "\e[92m[~] Total online.."
#   cat "$domain"_unique.txt | wc -l
   echo "******************************************************************************************"
#   cp "$domain"_unique.txt "$current"/"$domain"/"$subdirectory"/probing/
   echo "******************************************************************************************"
#   rm "$domain"_unique.txt "$domain"_Bunique.txt
   cd "$current"/"$domain"/"$subdirectory"/subdomains
#   cp "$domain"_unique.txt aquatone/
#   cd aquatone/
   echo -e "\e[92m[~] Passing file to aquatone"
   echo "*****************************************************************************************"
   sleep 1
#   sed -i 's/^/https:\/\//' "$domain"_unique.txt
   cat "$domain"_unique.txt | aquatone -ports xlarge -threads 20 -http-timeout 30000 -screenshot-timeout 90000 -out aquatone_result
   mv aquatone_result ../screenshot/
#   rm -rf "$domain"_unique.txt headers html aquatone_urls.txt
#   cd "$current"
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] Script will now scan for subdomain takeover"
   echo "*****************************************************************************************"
 #  sleep 2
#   cp "$domain"_unique.txt /root/go/src/github.com/haccer/subjack/
#   cd /root/go/src/github.com/haccer/subjack
#   echo -e "\e[92m[~] Directory changed.."
   echo -e "\e[92m[~] Subjack is in action.."
   echo "*****************************************************************************************"
   sed -e 's/https:\/\///g; s/http:\/\///g' "$domain"_unique.txt | sort -u >> subjack_input.txt
   sleep 2
   subjack -m -t 50 -timeout 20 -v -w subjack_input.txt -o ../subdomains/subjack_result.txt
   echo -e "\e[92m[~] subjack completed his task.."
   echo "*****************************************************************************************"
#   cd -
   echo -e "\e[92m[~] Subover is in action..."
   sleep 2
   cd /root/go/src/github.com/Ice3man543/SubOver/
   ./subover -l "$current"/"$domain"/"$subdirectory"/subdomains/subjack_input.txt -t 100 -timeout 30 -v -o "$current"/"$domain"/"$subdirectory"/subdomains/"$domain"_subover.txt
#   cp subjack_input.txt ../buckets/
   echo -e "\e[92m[~] subover completed his task.."
   echo "*****************************************************************************************"
   cd -
   cp subjack_input.txt /root/go/src/github.com/anshumanbh/tko-subs/
   cd /root/go/src/github.com/anshumanbh/tko-subs/
   echo "*****************************************************************************************"
   echo -e "\e[92m[~] Directory changed.."
   echo -e "\e[92m[~] tko-subs is in action.."
   echo "*****************************************************************************************"
   sleep 1
   ./tko-subs -domains subjack_input.txt -data providers-data.csv -threads 100
   echo "*****************************************************************************************"
   mv output.csv "$current"/"$domain"/"$subdirectory"/subdomains/"$domain"_tko-subs.csv
   cd "$current"/"$domain"/"$subdirectory"/subdomains/
   count=`wc -l "$domain"_tko-subs.csv | cut -d " " -f 1`
   if [ "$count" == 1 ]
   then
	echo -e "\e[31m[~] No takeovers found.."
	echo "************************************************************************************"
   else
	echo -e "\e[92m[~] Possible Takeovers found check manually.."
	cat "$domain"_tko-subs.csv
	echo "************************************************************************************"
   fi
   if [ -z "$module" ]
   then
	portscan
   else
	echo -e "\e[92m[~] $module completed results can be found in..$current/$domain/$subdirectory"
        echo "************************************************************************************"
        exit 0
   fi
}

helpFunction()
{
   echo ""
   echo -e "\e[91m[~] Usage: $0 -d example.com "
   echo -e "\t-d domain name for the recon"
   exit 1 # Exit script after printing help
}

#subdirectory=recon-$(date +"%Y-%m")

while getopts "d:h:m:s:b:w:" opt
do
   case "$opt" in
      d ) domain="$OPTARG" ;;
      m	) module="$OPTARG" ;;
      s ) ssrf="$OPTARG" ;;
      b ) blind="$OPTARG" ;;
      w ) wordlist="$OPTARG" ;;
      ? ) helpFunction ;; # Print helpFunction in case parameter is non-existent
   esac
done

user_directory(){
subdirectory="$directory"
}
auto_directory(){
subdirectory=recon-$(date +"%Y-%m-%d")
}
if [ -z "$directory" ]
then
        echo "helo"
        auto_directory
else
        echo "heello"
        user_directory
fi

mkdir ./"$domain"
mkdir ./"$domain"/"$subdirectory"
mkdir ./"$domain"/"$subdirectory"/subdomains
mkdir ./"$domain"/"$subdirectory"/directory
mkdir ./"$domain"/"$subdirectory"/probing
mkdir ./"$domain"/"$subdirectory"/screenshot
mkdir ./"$domain"/"$subdirectory"/buckets
mkdir ./"$domain"/"$subdirectory"/URLs
mkdir ./"$domain"/"$subdirectory"/portscan
mkdir ./"$domain"/"$subdirectory"/vulns
mkdir ./"$domain"/"$subdirectory"/github_recon

clear
if [ -z "$module" ]
then
	subdomain
else
	"$module"
fi

