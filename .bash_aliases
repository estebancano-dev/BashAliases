# scans for js files with https://github.com/ffuf/ffuf on a list of urls in a file
# usage: scanjs file.txt
# output: urls found with 200 http responses
scanjs(){
	now=$(date +"%Y%m%d%H%M%S")
	echo "Scanjs started $now. Log file: scanjs_$now.txt" | tee -a scanjs_$now.txt
	cat $1 | while read line; do 
		FILENAME=$line
		FUZZ="FUZZ"
		EXT=".js"
		echo "Scanning...$FILENAME$FUZZ$EXT" | tee -a scanjs_$now.txt
		echo "Wordlist 1.txt..." | tee -a scanjs_$now.txt
		SECONDS=0
		ffuf -u "$FILENAME$FUZZ$EXT" -s -c -mc "200" -w ~/tools/__diccionarios/1.txt | tee -a scanjs_$now.txt
		echo "Finished in $SECONDS seconds" | tee -a scanjs_$now.txt
		echo "Wordlist 2.txt..." | tee -a scanjs_$now.txt
		SECONDS=0
		ffuf -u "$FILENAME$FUZZ$EXT" -s -c -mc "200" -w ~/tools/__diccionarios/2.txt | tee -a scanjs_$now.txt
		echo "Finished in $SECONDS seconds" | tee -a scanjs_$now.txt
		echo "Wordlist 3.txt..." | tee -a scanjs_$now.txt
		SECONDS=0
		ffuf -u "$FILENAME$FUZZ$EXT" -s -c -mc "200" -w ~/tools/__diccionarios/3.txt | tee -a scanjs_$now.txt
		echo "Finished in $SECONDS seconds" | tee -a scanjs_$now.txt
		echo "Wordlist 4.txt..." | tee -a scanjs_$now.txt
		SECONDS=0
		ffuf -u "$FILENAME$FUZZ$EXT" -s -c -mc "200" -w ~/tools/__diccionarios/4.txt | tee -a scanjs_$now.txt
		echo "Finished in $SECONDS seconds" | tee -a scanjs_$now.txt
		echo "Wordlist 5.txt..." | tee -a scanjs_$now.txt
		SECONDS=0
		ffuf -u "$FILENAME$FUZZ$EXT" -s -c -mc "200" -w ~/tools/__diccionarios/5.txt | tee -a scanjs_$now.txt
		echo "Finished in $SECONDS seconds" | tee -a scanjs_$now.txt
	done
}

# scans for subdomains files with https://github.com/ffuf/ffuf on a list of urls in a file
# usage: scansub file.txt
# output: urls found with XXX http responses
scansub(){
	now=$(date +"%Y%m%d%H%M%S")
	h="http://FUZZ."
	http="http://"
	https="https://"
	echo "Scansub started $now. Log file: scansub_$now.txt" | tee -a scansub_$now.txt
	cat $1 | while read line; do
		if [ ${line:0:8} = "https://" ]; then
		    h="https://FUZZ."
		fi 
		foo=${line/$http/}
		foo=${line/$https/}
		echo "curl -s -H \"Host: nonexistent.$foo\" $line |wc -c"
		length=$(curl -s -H \"Host: nonexistent.$foo\" $line |wc -c)
		echo "ffuf -u \"$h$foo\" -s -c -w ~/tools/__diccionarios/1y4.txt -fs $length | tee -a scansub_$now.txt"
		#echo "Scanning...$line" | tee -a scansub_$now.txt
		#echo "Wordlist 1y4.txt..." | tee -a scansub_$now.txt
		#SECONDS=0
		#ffuf -u "$h$foo" -s -c -w ~/tools/__diccionarios/1y4.txt -fs $length | tee -a scansub_$now.txt
		#echo "Finished in $SECONDS seconds" | tee -a scansub_$now.txt
		#echo "Wordlist 3y2.txt..." | tee -a scansub_$now.txt
		#SECONDS=0
		#ffuf -u "$h$foo" -s -c -w ~/tools/__diccionarios/3y2.txt | tee -a scansub_$now.txt
		#echo "Finished in $SECONDS seconds" | tee -a scansub_$now.txt
	done
}

# creates a new file with unique and ordered lines from source file 
# usage: uniquelines file.txt
# output: fileunique.txt
uniquelines(){
	FILENAME=$1
	NEWFILENAME="${FILENAME%%.*}unique.${FILENAME#*.}"
	totallines=$(wc -l $FILENAME | awk '{ print $1 }')
	sort -u $FILENAME > $NEWFILENAME
	totalnewlines=$(wc -l $NEWFILENAME | awk '{ print $1 }')
	total=$((totallines - totalnewlines))
	echo "$total from $totallines duplicated lines deleted. File created: $NEWFILENAME"
}

# creates a new file with email accounts found in source file
# usage: grepemails file.txt
# output: fileemails.txt
grepemails(){
	FILENAME=$1
	grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $1 > "${FILENAME%%.*}emails.txt"
	echo "File created: ${FILENAME%%.*}emails.txt"
}

linkfinder(){
	cd ~/tools/LinkFinder
	python3 linkfinder.py -i $1 -d -o cli
}

ipinfo(){
	curl http://ipinfo.io/$1
}

check(){
	assetfinder $1 | grep $1 | httprobe
}

# Given a domain name, scans for subdomains, tries to resolve them, shows web services, check for alive ones and makes portscan
# Uses: amass, massdns, httprobe, nmap, masscan
# usage: subdomains domain.com
# output: list of pasive subdomains
subdomains(){
	echo -e "\e[32mDoing amass...\033[0m"
	mkdir -p tools/recon/$1
	amass enum -src -brute -min-for-recursive 2 -d $1 -o ~/tools/recon/$1/amass$1.txt > /dev/null 2>&1
	#amass enum --passive -d $1 -o ~/tools/recon/$1/amass$1.txt > /dev/null 2>&1
	echo -e "\e[32mDoing massdns...\033[0m"
	massdns -q -r ~/tools/massdns/lists/resolvers.txt -w ~/tools/recon/$1/massdns$1.txt ~/tools/recon/$1/amass$1.txt
	echo -e "\e[32m\nDoing httprobe...\033[0m"
	cat ~/tools/recon/$1/amass$1.txt | httprobe
	echo -e "\e[32m\nDoing Nmap to check if alive...\033[0m"
	nmap -sP -Pn -T5 -iL ~/tools/recon/$1/amass$1.txt > ~/tools/recon/$1/nmap$1.txt
	echo -e "\e[32m\nDoing Masscan...\033[0m"
	egrep -o -h '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' ~/tools/recon/$1/nmap$1.txt | sort -u > ~/tools/recon/$1/nmapips$1.txt
	masscan -p20,21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -iL ~/tools/recon/$1/nmapips$1.txt -oG ~/tools/recon/$1/masscan$1.txt
	echo -e "\e[32mThe End\033[0m"
}

#massdns(){
#	cd ~/tools/massdns/bin/
#	./massdns -q -r ~/tools/massdns/lists/resolvers.txt -w ~/tools/subd$1massdns.txt ~/tools/subd$1.txt
#}

getips(){
	egrep -o -h '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' $1 | sort -u > $1ips.txt
}

checkwebalive(){
	nmap -sn -Pn $1 --script hostmap-crtsh | awk '{ print $2 }' | grep $1 | check $1
}

# reloads aliases in current terminal without the need to close and start a new
reload(){
	source ~/.bash_aliases
	echo ".bash_aliases reloaded"
}
# updates OS?
update(){
	sudo apt update && sudo apt dist-upgrade -y
	#pip install --upgrade pip
	#pip-review --auto
	sudo apt autoremove
	sudo apt-get clean
	sudo apt-get autoclean
}

dirsearch(){
	PS3='Please enter your choice: '
	options=("dirsearch no ext" "all ext" "js" "js,_js,js_,js1,js2" "js w/ dicc 1-4" "custom ext" "Quit")
	select opt in "${options[@]}"
	do
		case $opt in
			"dirsearch no ext")
				python3 ~/tools/dirsearch/dirsearch.py --random-agents -x 301,302,400 -f -u $1 -e , -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"all ext")
				python3 ~/tools/dirsearch/dirsearch.py --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,bck,tmp,_js,_tmp,asp,aspx,php,php3,php4,php5,txt,shtm,shtml,phtm,phtml,jhtml,pl,jsp,cfm,cfml,py,rb,cfg,zip,pdf,gz,tar,tar.gz,tgz,doc,docx,xls,xlsx,conf -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"js")
				python3 ~/tools/dirsearch/dirsearch.py --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"js,_js,js_,js1,js2")
				python3 ~/tools/dirsearch/dirsearch.py --random-agents -x 301,302,400 -f -u $1 -e js,_js,js_,js1,js2 -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"js w/ dicc 1-4")
				python3 ~/tools/dirsearch/dirsearch.py --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/1y4.txt
				python3 ~/tools/dirsearch/dirsearch.py --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/3y2.txt
				break
				;;
			"custom ext")
				python3 ~/tools/dirsearch/dirsearch.py --random-agents -x 301,302,400 -f -u $1 -e $2 -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"Quit")
				break
				;;
			*) echo "invalid option $REPLY";;
		esac
	done
}

nmap2(){
	PS3='Please enter your choice: '
	options=("alive" "fast" "web vulns" "all ports" "Quit")
	select opt in "${options[@]}"
	do
		case $opt in
			"alive")
				nmap -sP -Pn -T5 $1
				break
				;;
			"fast")
				nmap -sS -Pn -T5 -F $1
				break
				;;
			"web vulns")
				nmap -sS -Pn -T5 -p80,443 --script "vuln" $1
				break
				;;
			"all ports")
				nmap -sS -Pn -T5 -p- --host-timeout 60m $1
				break
				;;
			"Quit")
				break
				;;
			*) echo "invalid option $REPLY";;
		esac
	done
}

sqlmap(){
	cd ~/tools/sqlmap
	python3 sqlmap.py -u $1 --level=5 --risk=3 --threads=10 --dump --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords
}

netcat(){
	nc -lvnp 3333
}

#para instalar todas las aplicaciones que utilizo
install(){
	cd ~
	mkdir -p tools/{__diccionarios,recon}
	cd tools
	sudo apt update && sudo apt dist-upgrade -y
	sudo apt-get install golang-go
	git clone https://github.com/maurosoria/dirsearch.git
	git clone https://github.com/blechschmidt/massdns.git
	cd massdns
	make
	git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
	git clone https://github.com/GerbenJavado/LinkFinder.git
	cd LinkFinder
	python setup.py install
	git clone https://github.com/robertdavidgraham/masscan
	cd masscan
	make
	pip3 install -r requirements.txt	
	go get -u github.com/tomnomnom/httprobe
	go get -u github.com/tomnomnom/assetfinder
	go get -u github.com/ffuf/ffuf
	reinstall
	sudo apt autoremove
	sudo apt-get clean
	sudo apt-get autoclean
}

# para descargar la ultima version de .bash_aliases y commonwords
reinstall(){
	echo -e "\e[32m"
	cd ~/
	mkdir -p tools/{__diccionarios,recon}
	git clone https://github.com/estebancano-dev/BashAliases.git
	cp ~/BashAliases/.bash_aliases ~/
	rm -R ~/BashAliases 
	git clone https://github.com/estebancano-dev/commonwords.git
	cp ~/commonwords/*.txt ~/tools/__diccionarios
	rm -R ~/commonwords 
	reload
	echo -e "\033[0m"
}
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
