#!/bin/bash
massdns=/root/scripts/bounty/massdns/bin/massdns
subdirectory=recon-$(date +"%Y-%m-%d")
domain=google.com
clear
banner=`figlet -f slant myrecon`
echo -e "\e[93;1m${banner}" 
echo -e "			\e[31;1m script by Shubham Chaskar\033[0m"
#echo -e "\e[5;92m scan completed successfully\033[0m"
echo ""
#if [ -d "./$domain" ]
#then
#	echo "exist"
#else
#	mkdir ./"$domain"
#fi
#mkdir ./"$domain"/"$subdirectory"
#mkdir ./"$domain"/"$subdirectory"/subdomains/
#touch final_gov.txt
#for ip in `cat login.gov.txt`
#do
#	host "$ip" | cut -d " " -f 4 | sed 's/alias//g' | sed 's/CNAME//g' | sed 's/address//g' | sed '/^$/d' >> final_gov.txt
#	cat final_gov.txt
#done

#ip=`cat masscan.txt | cut -d " " -f 1`

#for concat in `cat masscan1.txt`
#do
#	echo "$concat"
#done
a=1
b=`wc -l out.csv | cut -d " " -f 1`
echo "$b"
if [ "$b" == 1 ]
then
	echo "one"
else
	echo "Two"
fi

if ! command -v findomains &> /dev/null
then
	echo "not exist"
else
	echo "yes"
fi
#for host1 in `cat seek.com.au_unique1.txt`
#do
#	if [ $(curl -I "$host1" --write-out %{http_code} -m 3 --silent --output /dev/null) == 000 ]
#		then
#			echo "unreachable"
#			echo "Deleting $host1 from file"
#			sed -i "/${host1}/d" seek.com.au_unique.txt
#	else
#		echo "Reachable"
#	fi
#done
ff3(){
echo "hi"
echo "$wordlist"
}
portscan(){
echo "dalfox pipe -blind $blind "
echo "dalfox pipe -blind $ss "
ff3
echo "dalfox pipe -blind $blind "
echo "dalfox pipe -blind $blind "
}
subdomain(){
ss="$ssrf"
portscan
ss="$ssrf"
}
while getopts ":d:h:m:s:b:w:" opt
do
   case "$opt" in
      d ) domain="$OPTARG" ;;
      m ) module="$OPTARG" ;;
      s ) ssrf="$OPTARG" ;;
      b ) blind="$OPTARG" ;;
      w ) wordlist="$OPTARG" ;;
      ? ) helpFunction ;; # Print helpFunction in case parameter is non-existent
   esac
done

echo "$domain"
echo "$module"
#if [ -z "$module" ]
#then
 #       subdomain
#else
 #       "$module"
#fi

subdomain
