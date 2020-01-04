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
	cp ~/commonwords/*.* ~/tools/__diccionarios
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
# Uses: assetfinder, subfinder, sublist3r, amass, massdns, httprobe, nmap, masscan
# usage: subdomains domain.com
# output: list of alive subdomains and open ports
subdomains(){
	clear
	begin=$(date +"%s")
	now=$(date +"%Y%m%d%H%M")
	mkdir -p ~/tools/recon/$1/$now/
	cd ~/tools/recon/$1/$now/
	touch 1scrap1$1.txt 1scrap2$1.txt 1scrap3$1.txt 1scrap4$1.txt

	echo -e "\e[32mUrl: $1\033[0m"
	echo -e "\e[32m************ Starting Scrapping... ************\033[0m"
	echo -e "\e[32mDoing Assetfinder...\033[0m"
	assetfinder $1 > 1scrap1$1.txt	
	
	echo -e "\e[32mDoing Subfinder...\033[0m"
	subfinder -t 100 -d $1 -silent -o 1scrap2$1.txt > /dev/null 2>&1
	
	echo -e "\e[32mDoing Sublist3r...\033[0m"
	python ~/tools/Sublist3r/sublist3r.py -d $1 -o 1scrap3$1.txt > /dev/null 2>&1
	
	echo -e "\e[32mDoing Amass...\033[0m"
	amass enum -d $1 -o 1scrap4$1.txt > /dev/null 2>&1
	
	# junto los resultados, quito dominios que no sirven (si busco *.google.com a veces aparece ihategoogle.com, y no es parte del scope)
	# los ordeno y quito dominios duplicados
	cat *.txt | grep "\.$1\|^$1" > 1scrap$1.txt
	rm -f 1scrap1$1.txt 1scrap2$1.txt 1scrap3$1.txt 1scrap4$1.txt
	sort -u -o 1scrap$1.txt 1scrap$1.txt 
	echo -e "\e[32m************** Scrapping done... **************\033[0m"

	if [[ -f 1scrap$1.txt && ! -s 1scrap$1.txt ]]
	then
		echo -e "\e[32m*********** No domains scrapped... ************\033[0m"
		echo -e "\e[32m***********************************************\033[0m"
		return
	fi

	echo -e "\e[32m********** Starting DNS Resolving... **********\033[0m"
	echo -e "\e[32mDoing Massdns...\033[0m"
	massdns -q -r ~/tools/massdns/lists/resolvers.txt -w 2massdns$1.txt 1scrap$1.txt
	massdns -q -o S -r ~/tools/massdns/lists/resolvers.txt -w 8massdnssimple$1.txt 1scrap$1.txt
	echo -e "\e[32m************ DNS Resolving done... ************\033[0m"
	
	if [[ -f 2massdns$1.txt && ! -s 2massdns$1.txt ]]
	then
		echo -e "\e[32m*********** No domains resolved... ************\033[0m"
		echo -e "\e[32m***********************************************\033[0m"
		return
	fi
	
	echo -e "\e[32m********** Starting Alive Checking... *********\033[0m"
	echo -e "\e[32mDoing httprobe...\033[0m"
	cat 1scrap$1.txt | httprobe | tee 6httprobe$1.txt
	touch 7nmapvuln$1.txt 9httprobeXORsqli$1.txt
	
	# existen http o https accesibles, chequeo sqli y redirects
	if [[ -f 6httprobe$1.txt && -s 6httprobe$1.txt ]]
	then
		echo -e "\e[32m\nDoing Curl to check headers for sqli...\033[0m"
		checkheadersforsqli 6httprobe$1.txt 9httprobeXORsqli$1.txt
		echo -e "\e[32m\nDoing Curl to check headers for redirect...\033[0m"
		checkheadersforredirect 6httprobe$1.txt 9httprobeXORsqli$1.txt
	fi
	
	echo -e "\e[32m\nDoing Nmap to check if alive...\033[0m"
	nmap -sP -Pn -T5 -iL 1scrap$1.txt > 3nmap$1.txt < /dev/null 2>&1
	egrep -o -h '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' 3nmap$1.txt | sort -u > 4nmapips$1.txt
	echo -e "\e[32m************ Alive Checking done... ***********\033[0m"
	
	echo -e "\e[32m********** Starting Port scanning... **********\033[0m"
	if [[ -f 4nmapips$1.txt && -s 4nmapips$1.txt ]]
	then
		echo -e "\e[32mDoing Nmap to check top 2000 port vulns/versions...\033[0m"
		nmap -sS -Pn -T5 --data-length 35 --top-ports 2000 --script "vuln,version" -iL 4nmapips$1.txt > 7nmapvuln$1.txt < /dev/null 2>&1
	fi
	echo -e "\e[32mDoing Masscan...\033[0m"
	masscan -p1-65535 -iL 4nmapips$1.txt -oG 5masscan$1.txt > /dev/null 2>&1
	echo -e "\e[32m************* Port scanning done... ***********\033[0m"
	
	echo -e "\e[32m***************** Final results ***************\033[0m"
	cat 8massdnssimple$1.txt 5masscan$1.txt 7nmapvuln$1.txt 9httprobeXORsqli$1.txt
	echo -e "\e[32m***********************************************\033[0m"
	end=$(date +"%s")
	diff=$(($end-$begin))
	echo "$(($diff / 60))m $(($diff % 60))s elapsed."
}

# Gets an url with curl and adds every header to check for potential sqli injections (if response time > 6 seconds)
# usage: checkheadersforsqli urllist.txt outputheaderswithsqli.txt
# output: list of urls and headers with potential sqli
checkheadersforsqli(){
	echo "******** Checking headers for sqli... *********" > $2
	cat $1 | while read url; do
		cat ~/tools/__diccionarios/headers.txt | while read head; do
			response=$(curl -X GET -H 'User-Agent:' -H "$head: \"XOR(if(now()=sysdate(),sleep(6),0))OR\"" -s -I -L -w "REQUESTTIME %{time_starttransfer}" $url)
			time=$(echo $response | tail -1)
			if [$time -gt 6]
			then
				echo "\r\n*** URL: $url - Header: $head\r\n" >> $2
				echo $response >> $2
			fi
		done
	done
}

# Gets an url with curl and adds every header to check for sqli injections (if response time > 6 seconds)
# usage: checkheadersforredirect urllist.txt outputurlswithredirection.txt
# output: list of urls and headers with redirection
checkheadersforredirect(){
	echo "****** Checking headers for redirect... *******" > $2
	cat $1 | while read url; do
		response=$(curl -X GET -H "X-Forwarded-For: estebancano.com.ar/abc.php?$url" -s -L $url)
		grep -q '<!-- CHECK -->' <<< $var && echo "\r\n*** URL: $url - Header: X-Forwarded-For: estebancano.com.ar/abc.php?$url" >> $2
		response=$(curl -X GET -H "X-Forwarded-Host: estebancano.com.ar/abc.php?$url" -s -L $url)
		grep -q '<!-- CHECK -->' <<< $var && echo "\r\n*** URL: $url - Header: X-Forwarded-For: estebancano.com.ar/abc.php?$url" >> $2
	done
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
	options=("no ext" "no ext dicc" "no ext file" "all ext" "js" "php" "js dicc 1-4" "custom ext" "custom ext dicc 1-5" "Quit")
	select opt in "${options[@]}"
	do
		case $opt in
			"no ext")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -u $1 -e ,
				break
				;;
			"no ext dicc")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -u $1 -e , -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"no ext file")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -L $1 -e ,
				break
				;;
			"all ext")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -u $1 -e ,json,js,html,htm,html~,htm~,bck,bck~,tmp,_js,js~,_tmp,tmp~,asp,aspx,inc.php,php,php~,txt,txt~,pl,jsp,jsp~,py,rb,cfg,cfg~,zip,zip~,pdf,gz,gz~,tar,tar~,tar.gz,tar.gz~,tgz,doc,doc~,docx,xls,xlsx,conf,conf~,do,action -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"js")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -u $1 -e js,js~ -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"php")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -u $1 -e php,inc.php,php~ -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"js dicc 1-4")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/1-4.txt
				break
				;;
			"custom ext")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -u $1 -e $2 -w ~/tools/__diccionarios/commonwords.txt
				break
				;;
			"custom ext dicc 1-5")
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 -f -u $1 -e $2 -w ~/tools/__diccionarios/1-5.txt
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
	go get -v github.com/projectdiscovery/subfinder/cmd/subfinder
	reinstall
	sudo apt autoremove
	sudo apt-get clean
	sudo apt-get autoclean
}


export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
