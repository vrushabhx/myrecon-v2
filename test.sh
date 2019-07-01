#!/bin/bash
massdns=/root/scripts/bounty/massdns/bin/massdns
subdirectory=recon-$(date +"%Y-%m-%d")
domain=google.com
clear
banner=`figlet -f slant myrecon`
echo -e "\e[93;1m${banner}" 
echo -e "			\e[31;1m script by Shubham Chaskar"
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

for concat in `cat masscan1.txt`
do
	echo "$concat"
done

read1()
{
cat 123.txt
echo -e "\e[93;1m${banner}" 
echo -e "                       \e[31;1m script by Shubham Chaskar"
echo "Just a blind test"
#$massdns 
#altdns
}
write()
{
echo "hi" > 123.txt
$(read1)
}
file()
{
touch 123.txt
write
}
file
massdns
