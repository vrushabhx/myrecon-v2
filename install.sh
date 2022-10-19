#!/bin/bash

clear

echo -e "\e[92m[~] Installing nmap,figlet,pip3,pip2, chromium..\e[00m\n"
sudo add-apt-repository restricted
apt update
#sudo apt-get install make make-guile -y
#sudo apt -f install
sudo apt install snapd -y
sudo apt install unzip -y
sudo apt install figlet -y
sudo apt install python2 -y
sudo apt install python-minimal -y
sudo apt install python2-minimal -y
sudo apt install python3-pip -y
sudo apt install build-essential -y
sudo apt install moreutils -y
sudo apt install gcc -y
sudo rm /var/cache/apt/archives/chromium*
sudo apt install chromium-browser -y
sudo apt install perl -y
snap install jq
snap install nmap
snap connect nmap:network-control
apt install -y libpcap-dev
source $HOME/.cargo/env

if ! command -v pip2 &> /dev/null
then
        echo -e "\e[92m[~] Not able to find pip2..Installing..\e[00m\n"
	curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
	python2 get-pip.py
else
        echo -e "\e[31m[!] Skipping installation for pip2..\e[00m\n"
fi

if ! command -v cargo &> /dev/null
then
	echo -e "\e[92m[~] Not able to find rust..Installing..\e[00m\n"
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	source $HOME/.cargo/env
	echo "source $HOME/.cargo/env" >> /root/.bashrc
	source /root/.bashrc
else
	echo -e "\e[31m[!] Skipping installation for rust..\e[00m\n"
fi

if ! command -v go &> /dev/null
then
	echo -e "\e[92m[~] Not able to find go..Installing..\e[00m\n"
	cd /root
	wget "https://go.dev/dl/go1.19.2.linux-amd64.tar.gz"
	tar -C /usr/local -xzf go1.19.2.linux-amd64.tar.gz
	export GOPATH=/root/go
	echo "export GOPATH=/root/go" >> /root/.bashrc
	source /root/.bashrc
	export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
	echo "export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin"	>> /root/.bashrc
	source /root/.bashrc
else
	echo -e "\e[31m[!] Skipping installation for Go..\e[00m\n"
fi

mkdir -p /root/scripts/bounty/
cd /root/scripts/bounty/
echo -e "\e[92m[~] Make sure you have installed go,python3,python2,rust,make,perl.."

echo -e "\e[92m[~] Checking if findomain exist or not..\e[00m"

if ! command -v findomain &> /dev/null
then
        echo -e "\e[92m[~] Not able to find findomain..Installing..\e[00m\n"
	git clone https://github.com/Edu4rdSHL/findomain.git
	cd findomain
	cargo build --release
	cp ./target/release/findomain /usr/local/bin/findomain
	cd ../
	echo -e "\e[93m[~] Configure API keys for better result..\e[00m\n"
else
        echo -e "\e[31m[!] Skipping installation for findomain..\e[00m\n"
fi

if ! command -v amass &> /dev/null
then
	echo -e "\e[92m[~] Not able to find amass..Installing..\e[00m\n"
	snap install amass
	cd /root/scripts/bounty/
	echo -e "\e[93m[~] Configure API keys for better result..\e[00m\n"
else
        echo -e "\e[31m[!] Skipping installation for amass..\e[00m\n"
fi

if ! command -v massdns &> /dev/null
then
        echo -e "\e[92m[~] Not able to find massdns..Installing..\e[00m\n"
        git clone https://github.com/blechschmidt/massdns.git
	cd massdns/
	make
	if ! command -v massdns &> /dev/null
	then
		echo -e "\e[93m[~] copying massdns manually..\e[00m\n"
		cp bin/massdns /usr/local/bin/massdns
	else
		echo -e "\e[31m[!] Some problem with your system fix the issue for massdns and then continue..\e[00m\n"
		exit 1
	fi
	cd ../
else
        echo -e "\e[31m[!] Skipping installation for massdns..\e[00m\n"
fi

if [ -d github-search ]
then
	echo -e "\e[31m[!] github-search already exist.. skipping installation..\e[00m\n"
	echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing github-search repo..\e[00m\n"
	git clone https://github.com/gwen001/github-search.git
	cd github-search/
	pip3 install -r requirements3.txt
	pip2 install -r requirements2.txt
	cd ../
	echo -e "\e[93m[~] Configure github_token in .tokens..\e[00m\n"
fi

if [ -d Interlace ]
then
	echo -e "\e[31m[!] Interlace already exist.. skipping installation..\e[00m\n"
        echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing interlace..\e[00m\n"
	git clone https://github.com/codingo/Interlace.git
	cd Interlace/
	python3 setup.py install
	cd ../
fi

if [ -d cloud_enum ]
then
	echo -e "\e[31m[!] cloud_enum already exist.. skipping installation..\e[00m\n"
	echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing cloud_enum..\e[00m\n"
	git clone https://github.com/initstring/cloud_enum.git
	cd cloud_enum/
	pip3 install -r requirements.txt
	wget https://raw.githubusercontent.com/RhinoSecurityLabs/GCPBucketBrute/master/permutations.txt
	cp permutations.txt all.txt
	cd ../
fi

if [ -d LinkFinder ]
then
	echo -e "\e[31m[!] LinkFinder already exist.. skipping installation..\e[00m\n"
        echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing Linkfinder..\e[00m\n"
	git clone https://github.com/GerbenJavado/LinkFinder.git
	cd LinkFinder/
	pip3 install -r requirements.txt
	python3 setup.py install
	cd ../
fi

if [ -d Arjun ]
then
	echo -e "\e[31m[!] Arjun already exist.. skipping installation..\e[00m\n"
        echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing Arjun..\e[00m\n"
	git clone https://github.com/s0md3v/Arjun.git
	cd Arjun
	python3 setup.py install
	cd ../
fi

if [ -d tplmap ]
then
	echo -e "\e[31m[!] tplmap already exist.. skipping installation..\e[00m\n"
        echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing tplmap..\e[00m\n"
	git clone https://github.com/epinna/tplmap.git
	cd tplmap/
	pip install -r requirements.txt
	pip2 install -r requirements.txt
	cd ../
fi

if [ -d pentest-tools ]
then
	echo -e "\e[31m[!] pentest-tools already exist.. skipping installation..\e[00m\n"
        echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing pentest-tools..\e[00m\n"
	git clone https://github.com/gwen001/pentest-tools.git
	cd pentest-tools/
	pip3 install -r requirements3.txt
	pip2 install -r requirements2.txt
	wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt
	cd ../

fi

if [ -d sqlmap-dev ]
then
	echo -e "\e[31m[!] sqlmap-dev already exist.. skipping installation..\e[00m\n"
        echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing sqlmap..\e[00m\n"
	git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
fi

if [ -d gitGraber ]
then
	echo -e "\e[31m[!] gitGraber already exist.. skipping installation..\e[00m\n"
        echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing gitGraber..\e[00m\n"
	git clone https://github.com/hisxo/gitGraber.git
	cd gitGraber/
	pip3 install -r requirements.txt
	cd wordlists/
	cat * > all_keywords.txt
	echo -e "\e[93m[~] Edit config.py with github and slack tokens..\e[00m\n"
fi
cd /root/scripts/bounty/

if [ -d smuggler ]
then
	echo -e "\e[31m[!] smuggler already exist.. skipping installation..\e[00m\n"
        echo -e "\e[93m[~] To update specific tools use git pull from tool directory..\e[00m\n"
else
	echo -e "\e[92m[~] Installing smuggler..\e[00m\n"
	git clone https://github.com/defparam/smuggler.git
fi


echo "***************************************************************************************"
echo -e "\e[92m[~] Installing GO tools.."
#echo -e "\e[92m[~] setting GOPATH for you.."
#echo "export GOPATH=$HOME/work" >> /root/.bashrc
#echo "export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin" >> /root/.bashrc
#echo "export GOPATH=$HOME/go" >> /root/.bashrc
#echo "PATH=$GOPATH/bin:$PATH" >> /root/.bashrc
#echo "export GOROOT=/root/.go" >> /root/.bashrc
#echo "export GOPATH=/root/go" >> /root/.bashrc
#echo "export PATH=$PATH:$GOROOT/bin:$GOPATH/bin" >> /root/.bashrc

if ! command -v assetfinder &> /dev/null
then
	echo -e "\e[92m[~] Installing assetfinder.."
	go install -v github.com/tomnomnom/assetfinder@latest
else
	echo -e "\e[31m[!] assetfinder already exist..skipping"
fi

if ! command -v subfinder &> /dev/null
then
	echo -e "\e[92m[~] Installing subfinder..\e[00m\n"
	go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
else
	echo -e "\e[31m[!] subfinder already exist..skipping"
fi

if ! command -v httprobe &> /dev/null
then
	echo -e "\e[92m[~] Installing httprobe.."
	go install -v github.com/tomnomnom/httprobe@latest
else
	echo -e "\e[31m[!] httprobe already exist..skipping"
fi

if ! command -v aquatone &> /dev/null
then
	echo -e "\e[92m[~] Installing aquatone..\e[00m\n"
	wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
	unzip aquatone_linux_amd64_1.7.0.zip
	cp aquatone /usr/local/bin/aquatone
else
	echo -e "\e[31m[!] aquatone already exist..skipping"
fi

if ! command -v naabu &> /dev/null
then
	echo -e "\e[92m[~] Installing naabu..\e[00m\n"
	sudo apt install -y libpcap-dev
	go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	
else
	echo -e "\e[31m[!] naabu already exist..skipping"
fi

if ! command -v ffuf &> /dev/null
then
	echo -e "\e[92m[~] Installing ffuf.."
	go install -v github.com/ffuf/ffuf@latest
else
	echo -e "\e[31m[!] ffuf already exist..skipping"
fi

if ! command -v waybackurls &> /dev/null
then
	echo -e "\e[92m[~] Installing Waybackurl.."
	go install -v github.com/tomnomnom/waybackurls@latest
else
	echo -e "\e[31m[!] waybackurls already exist..skipping"
fi

if ! command -v gau &> /dev/null
then
	echo -e "\e[92m[~] Installing gau.."
	go install -v github.com/lc/gau/v2/cmd/gau@latest
else
	echo -e "\e[31m[!] gau already exist..skipping"
fi

if ! command -v gospider &> /dev/null
then
	echo -e "\e[92m[~] Installing gospider.."
	GO111MODULE=on go install -v github.com/jaeles-project/gospider@latest
else
	echo -e "\e[31m[!] gospider already exist..skipping"
fi

if ! command -v jaeles &> /dev/null
then
	echo -e "\e[92m[~] Installing jaeles.."
	GO111MODULE=on go install -v github.com/jaeles-project/jaeles@latest
	jaeles config init
	cd /root/scripts/bounty/
else
	echo -e "\e[31m[!] jaeles already exist..skipping"
fi

if ! command -v nuclei &> /dev/null
then
	echo -e "\e[92m[~] Installing nuclei..\e[00m\n"
	go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
	nuclei -update-templates
else
	echo -e "\e[31m[!] nuclei already exist..skipping"
fi

if ! command -v kxss &> /dev/null
then
	echo -e "\e[92m[~] Installing kxss..\e[00m\n"
	cd /root/scripts/bounty/
	git clone https://github.com/tomnomnom/hacks.git
	cd hacks/kxss/
	go build main.go
	cp main /usr/local/bin/kxss
else
	echo -e "\e[31m[!] kxss already exist..skipping"
fi

if ! command -v dalfox &> /dev/null
then
	echo -e "\e[92m[~] Installing dalfox..\e[00m\n"
	go install -v github.com/hahwul/dalfox/v2@latest
else
	echo -e "\e[31m[!] dalfox already exist..skipping"
fi

if ! command -v gf &> /dev/null
then
	echo -e "\e[92m[~] Installing gf.."
	go install -v github.com/tomnomnom/gf@latest
	echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> /root/.bashrc
	mkdir /root/.gf
	cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf
else
	echo -e "\e[31m[!] gf already exist..skipping"
fi

if ! command -v crlfuzz &> /dev/null
then
	echo -e "\e[92m[~] Installing crlfuzz.."
	GO111MODULE=on go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
else
	echo -e "\e[31m[!] crlfuzz already exist..skipping"
fi

if ! command -v gowitness &> /dev/null
then
	echo -e "\e[92m[~] Installing gowitness.."
	go install -v github.com/sensepost/gowitness@latest
else
	echo -e "\e[31m[!] gowitness already exist..skipping"
fi

cd /root/scripts/bounty/
if [ -d Gf-Patterns ]
then
	echo -e "\e[31m[!] gf-patterns already exist..skipping"
else
	echo -e "\e[92m[~] Installing gf-patterns..\e[00m\n"
	cd /root/scripts/bounty
	git clone https://github.com/1ndianl33t/Gf-Patterns
	mv /root/scripts/bounty/Gf-Patterns/*.json /root/.gf
fi

if ! command -v qsreplace &> /dev/null
then
	echo -e "\e[92m[~] Installing qsreplace..\e[00m\n"
	go install -v github.com/tomnomnom/qsreplace@latest
else
	echo -e "\e[31m[!] qsreplace already exist..skipping"
fi

if ! command -v unfurl &> /dev/null
then
	echo -e "\e[92m[~] Installing unfurl.."
	go install -v github.com/tomnomnom/unfurl@latest
else
	echo -e "\e[31m[!] unfurl already exist..skipping"
fi

if ! command -v hakcheckurl &> /dev/null
then
	echo -e "\e[92m[~] Installing hakcheckurl.."
	go install -v github.com/hakluke/hakcheckurl@latest
else
	echo -e "\e[31m[!] Hakcheckurl already exist..skipping"
fi


if ! command -v slackcat &> /dev/null
then
        echo -e "\e[92m[~] Installing Slackcat..\e[00m\n"
	go install -v github.com/dwisiswant0/slackcat@latest
else
        echo -e "\e[92m[!] Slackcat already exist..skipping"
	echo -e "\e[93m[~] Configure slack_webhook in .tokens.."
fi

if ! command -v httpx &> /dev/null
then
        echo -e "\e[92m[~] Installing httpx..\e[00m\n"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
else
        echo -e "\e[92m[!] httpx already exist..skipping"
fi

cd /root/scripts/bounty/
if [ -d wordlists ]
then
	cd wordlists/
	if [ -f all.txt ]
	then
		echo -e "\e[31m[!] Jhaddix's file is already downloaded.."
	else
		wget https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/f58e82c9abfa46a932eb92edbe6b18214141439b/all.txt
	fi
	if [ -f subdomains.txt ]
	then
		echo -e "\e[31m[!] Directory file from assetnote file is already downloaded.."
	else
		wget https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt
		cat subdomains.txt all.txt | sort -u > dns_wordlist.txt
	fi
	if [ -f LFI-Jhaddix.txt ]
	then
		echo -e "\e[31m[!] Payloads for LFI testing are already downloaded.."
	else
		wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt
	fi
fi
echo -e "\e[92m[~] Installation completed..\e[00m"
