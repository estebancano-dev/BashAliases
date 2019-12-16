# reloads aliases in current terminal without the need to close and start a new
reload(){
	source ~/.bash_aliases
	echo ".bash_aliases reloaded"
}

# para descargar la ultima version de .bash_aliases y commonwords
reinstall(){
	echo -e "\e[32m"
	cd ~/
	mkdir -p ~/tools/{__diccionarios,recon}
	git clone https://github.com/estebancano-dev/BashAliases.git
	cp ~/BashAliases/.bash_aliases ~/
	rm -R ~/BashAliases 
	git clone https://github.com/estebancano-dev/commonwords.git
	cp ~/commonwords/*.txt ~/tools/__diccionarios
	rm -R ~/commonwords 
	reload
	echo -e "\033[0m"
}

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
# Uses: assetfinder, sublist3r, amass, massdns, httprobe, nmap, masscan
# usage: subdomains domain.com
# output: list of alive subdomains and open ports
subdomains(){
	mkdir -p ~/tools/recon/$1
	touch ~/tools/recon/$1/1scrap1$1.txt ~/tools/recon/$1/1scrap2$1.txt ~/tools/recon/$1/1scrap3$1.txt
	echo -e "\e[32m************ Starting Scrapping... ************\033[0m"
	
	echo -e "\e[32mDoing Assetfinder...\033[0m"
	assetfinder $1 > ~/tools/recon/$1/1scrap1$1.txt
	
	echo -e "\e[32mDoing Sublist3r...\033[0m"
	python ~/tools/Sublist3r/sublist3r.py -d $1 -o ~/tools/recon/$1/1scrap2$1.txt > /dev/null 2>&1
	
	echo -e "\e[32mDoing Amass...\033[0m"
	amass enum -d $1 -o ~/tools/recon/$1/1scrap3$1.txt > /dev/null 2>&1
	
	# junto los resultados, quito dominios que no sirven (si busco *.google.com a veces aparece ihategoogle.com, y no es parte del scope)
	# los ordeno y quito dominios duplicados
	cat ~/tools/recon/$1/*.txt | grep "\.$1\|^$1" > ~/tools/recon/$1/1scrap$1.txt
	rm -f ~/tools/recon/$1/1scrap1$1.txt ~/tools/recon/$1/1scrap2$1.txt ~/tools/recon/$1/1scrap3$1.txt
	sort -u -o ~/tools/recon/$1/1scrap$1.txt ~/tools/recon/$1/1scrap$1.txt 
	echo -e "\e[32m************** Scrapping done... **************\033[0m"

	if [[ -f ~/tools/recon/$1/1scrap$1.txt && ! -s ~/tools/recon/$1/1scrap$1.txt ]]
	then
		echo -e "\e[32m*********** No domains scrapped... ************\033[0m"
		echo -e "\e[32m***********************************************\033[0m"
		return
	fi

	echo -e "\e[32m********** Starting DNS Resolving... **********\033[0m"
	echo -e "\e[32mDoing Massdns...\033[0m"
	massdns -q -r ~/tools/massdns/lists/resolvers.txt -w ~/tools/recon/$1/2massdns$1.txt ~/tools/recon/$1/1scrap$1.txt
	massdns -q -o S -r ~/tools/massdns/lists/resolvers.txt -w ~/tools/recon/$1/8massdnssimple$1.txt ~/tools/recon/$1/1scrap$1.txt
	echo -e "\e[32m************ DNS Resolving done... ************\033[0m"
	if [[ -f ~/tools/recon/$1/2massdns$1.txt && ! -s ~/tools/recon/$1/2massdns$1.txt ]]
	then
		echo -e "\e[32m*********** No domains resolved... ************\033[0m"
		echo -e "\e[32m***********************************************\033[0m"
		return
	fi
	
	echo -e "\e[32m********** Starting Alive Checking... *********\033[0m"
	echo -e "\e[32mDoing httprobe...\033[0m"
	cat ~/tools/recon/$1/1scrap$1.txt | httprobe | tee ~/tools/recon/$1/6httprobe$1.txt
	touch ~/tools/recon/$1/7nmapvuln$1.txt
	
	echo -e "\e[32m\nDoing Nmap to check if alive...\033[0m"
	nmap -sP -Pn -T5 -iL ~/tools/recon/$1/1scrap$1.txt > ~/tools/recon/$1/3nmap$1.txt < /dev/null 2>&1
	egrep -o -h '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' ~/tools/recon/$1/3nmap$1.txt | sort -u > ~/tools/recon/$1/4nmapips$1.txt
	echo -e "\e[32m************ Alive Checking done... ***********\033[0m"
	
	echo -e "\e[32m********** Starting Port scanning... **********\033[0m"
	if [[ -f ~/tools/recon/$1/4nmapips$1.txt && -s ~/tools/recon/$1/4nmapips$1.txt ]]
	then
		echo -e "\e[32mDoing Nmap to check for top 100 port vulns...\033[0m"
		nmap -sS -Pn -T5 --top-ports 100 --script "vuln" -iL ~/tools/recon/$1/4nmapips$1.txt > ~/tools/recon/$1/7nmapvuln$1.txt < /dev/null 2>&1
	fi
	echo -e "\e[32mDoing Masscan...\033[0m"
	masscan -p1-1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000 -iL ~/tools/recon/$1/4nmapips$1.txt -oG ~/tools/recon/$1/5masscan$1.txt > /dev/null 2>&1
	echo -e "\e[32m************* Port scanning done... ***********\033[0m"
	
	echo -e "\e[32m***************** Final results ***************\033[0m"
	cd ~/tools/recon/$1
	cat 8massdnssimple$1.txt 5masscan$1.txt 7nmapvuln$1.txt
	echo -e "\e[32m***********************************************\033[0m"
}

getips(){
	egrep -o -h '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' $1 | sort -u > $1ips.txt
}

checkwebalive(){
	nmap -sn -Pn $1 --script hostmap-crtsh | awk '{ print $2 }' | grep $1 | check $1
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
	options=("no ext" "no ext dicc" "all ext" "js" "js,_js,js_,js1,js2,~js" "js dicc 1-4" "custom ext" "all ext dicc 1-4" "Quit")
	select opt in "${options[@]}"
	do
		case $opt in
			"no ext")
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e ,
				break
				;;
			"no ext dicc")
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e , -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"all ext")
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,~html,~htm,bck,~bck,tmp,_js,~js,_tmp,~tmp,asp,aspx,php,~php,txt,~txt,pl,jsp,~jsp,py,rb,cfg,~cfg,zip,~zip,pdf,gz,~gz,tar,~tar,tar.gz,~tar.gz,tgz,doc,~doc,docx,xls,xlsx,conf,~conf,do,action -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"js")
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"js,_js,js_,js1,js2,~js")
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e js,_js,js_,js1,js2,~js -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"js dicc 1-4")
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/1.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/2.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/3.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/4.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/5.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/6.txt
				break
				;;
			"custom ext")
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e $2 -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"all ext dicc 1-4")
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,~html,~htm,bck,~bck,tmp,_js,~js,_tmp,~tmp -w ~/tools/__diccionarios/1.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e asp,aspx,php,~php,txt,~txt,pl,jsp,~jsp,py,rb,cfg,~cfg,zip,~zip -w ~/tools/__diccionarios/1.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e pdf,gz,~gz,tar,~tar,tar.gz,~tar.gz,tgz,doc,~doc,docx,xls,xlsx,conf,~conf,do,action -w ~/tools/__diccionarios/1.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,~html,~htm,bck,~bck,tmp,_js,~js,_tmp,~tmp -w ~/tools/__diccionarios/2.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e asp,aspx,php,~php,txt,~txt,pl,jsp,~jsp,py,rb,cfg,~cfg,zip,~zip -w ~/tools/__diccionarios/2.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e pdf,gz,~gz,tar,~tar,tar.gz,~tar.gz,tgz,doc,~doc,docx,xls,xlsx,conf,~conf,do,action -w ~/tools/__diccionarios/2.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,~html,~htm,bck,~bck,tmp,_js,~js,_tmp,~tmp -w ~/tools/__diccionarios/3.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e asp,aspx,php,~php,txt,~txt,pl,jsp,~jsp,py,rb,cfg,~cfg,zip,~zip -w ~/tools/__diccionarios/3.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e pdf,gz,~gz,tar,~tar,tar.gz,~tar.gz,tgz,doc,~doc,docx,xls,xlsx,conf,~conf,do,action -w ~/tools/__diccionarios/3.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,~html,~htm,bck,~bck,tmp,_js,~js,_tmp,~tmp -w ~/tools/__diccionarios/4.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e asp,aspx,php,~php,txt,~txt,pl,jsp,~jsp,py,rb,cfg,~cfg,zip,~zip -w ~/tools/__diccionarios/4.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e pdf,gz,~gz,tar,~tar,tar.gz,~tar.gz,tgz,doc,~doc,docx,xls,xlsx,conf,~conf,do,action -w ~/tools/__diccionarios/4.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,~html,~htm,bck,~bck,tmp,_js,~js,_tmp,~tmp -w ~/tools/__diccionarios/5.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e asp,aspx,php,~php,txt,~txt,pl,jsp,~jsp,py,rb,cfg,~cfg,zip,~zip -w ~/tools/__diccionarios/5.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e pdf,gz,~gz,tar,~tar,tar.gz,~tar.gz,tgz,doc,~doc,docx,xls,xlsx,conf,~conf,do,action -w ~/tools/__diccionarios/5.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,~html,~htm,bck,~bck,tmp,_js,~js,_tmp,~tmp -w ~/tools/__diccionarios/6.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e asp,aspx,php,~php,txt,~txt,pl,jsp,~jsp,py,rb,cfg,~cfg,zip,~zip -w ~/tools/__diccionarios/6.txt
				python3 ~/tools/dirsearch/dirsearch.py -t 20 --random-agents -x 301,302,400 -f -u $1 -e pdf,gz,~gz,tar,~tar,tar.gz,~tar.gz,tgz,doc,~doc,docx,xls,xlsx,conf,~conf,do,action -w ~/tools/__diccionarios/6.txt
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
	cd ~/tools/sqlmap-dev
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


export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
