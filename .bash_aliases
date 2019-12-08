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

subdomains(){
	echo -e "\e[32mDoing amass..."
	#amass enum -src -brute -min-for-recursive 2 -d $1 | awk -F ']' '{print $2}' > ~/tools/subd$1.txt
	amass enum --passive -d $1 -o ~/tools/subd$1.txt > /dev/null 2>&1
	echo -e "\e[32mDoing massdns..."
	massdns $1
	echo -e "\e[32mmassdns results..."
	cat ~/tools/subd$1.txt
	echo -e "\e[32mDoing httprobe..."
	cat ~/tools/subd$1.txt | httprobe
	echo -e "\033[0m"
}

massdns(){
	cd ~/tools/massdns/bin/
	./massdns -r ~/tools/massdns/lists/resolvers.txt -w ~/tools/subd$1massdns.txt ~/tools/subd$1.txt
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

#------ Tools ------
dirsearch(){
	PS3='Please enter your choice: '
	options=("dirsearch no ext" "all ext" "js" "js,_js,js_,js1,js2" "js w/ dicc 1-4" "Quit")
	select opt in "${options[@]}"
	do
		case $opt in
			"dirsearch no ext")
				dirsearch1 $1
				break
				;;
			"all ext")
				dirsearch2 $1
				break
				;;
			"js")
				dirsearch3 $1
				break
				;;
			"js,_js,js_,js1,js2")
				dirsearch4 $1
				break
				;;
			"js w/ dicc 1-4")
				dirsearch5 $1
				break
				;;
			"Quit")
				break
				;;
			*) echo "invalid option $REPLY";;
		esac
	done
}
dirsearch1(){
	cd ~/tools/dirsearch
	python3 dirsearch.py -x 301,302,400 -f -u $1 -e , -w ~/tools/__diccionarios/commonwords.txt
}
dirsearch2(){
	cd ~/tools/dirsearch
	python3 dirsearch.py -x 301,302,400 -f -u $1 -e ,json,js,html,htm,bck,tmp,_js,_tmp,asp,aspx,php,php3,php4,php5,txt,shtm,shtml,phtm,phtml,jhtml,pl,jsp,cfm,cfml,py,rb,cfg,zip,pdf,gz,tar,tar.gz,tgz,doc,docx,xls,xlsx,conf -w ~/tools/__diccionarios/commonwords.txt
}
dirsearch3(){
	cd ~/tools/dirsearch
	python3 dirsearch.py -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/commonwords.txt
}
dirsearch4(){
	cd ~/tools/dirsearch
	python3 dirsearch.py -x 301,302,400 -f -u $1 -e js,_js,js_,js1,js2 -w ~/tools/__diccionarios/commonwords.txt
}
dirsearch5(){
	cd ~/tools/dirsearch
	python3 dirsearch.py -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/1y4.txt
	python3 dirsearch.py -x 301,302,400 -f -u $1 -e js -w ~/tools/__diccionarios/3y2.txt
}

sqlmap(){
	cd ~/tools/sqlmap
	python3 sqlmap.py -u $1 --level=5 --risk=3 --threads=10 --dump --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords
}

map(){
	nmap -p80,443 --script "vuln" $1
	
	#nmap -sS --data-length 15 --badsum -f --script=$1
}

netcat(){
	nc -lvnp 3333
}

# recon esteban
recon(){
	dig +nocmd $1 any +multiline +noall +answer

	#curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1 > ~/recon/$1.txt
	#cd ~/tools/dirsearch
	#cat ~/recon/$1.txt | while read line; do httprobe $line > ~/recon/$1_httprobe.txt; done | 
	#cat ~/recon/$1_httprobe.txt | while read line; do python3 dirsearch.py -f -u $1 -e json,js,html 
	#,htm,bck,tmp,_js,_tmp,asp,aspx,php,php3,php4,php5,txt,shtm,shtml,phtm,phtml,jhtml,pl,jsp,cfm,cfml,py,rb,cfg,zip,pdf,gz,tar,tar.gz,tgz,doc,docx,xls,xlsx,conf;
	#done

}
#para instalar todas las aplicaciones que utilizo
install(){
	cd ~
	mkdir tools
	cd tools
	sudo apt update && sudo apt dist-upgrade -y
	#sudo apt-get -y install python3-pip
	#pip install pip-review
	sudo apt-get install golang-go
	git clone https://github.com/maurosoria/dirsearch.git
	git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
	git clone https://github.com/GerbenJavado/LinkFinder.git
	cd LinkFinder
	python setup.py install
	pip3 install -r requirements.txt	
	go get -u github.com/tomnomnom/httprobe
	go get -u github.com/tomnomnom/assetfinder
	go get -u github.com/ffuf/ffuf
	sudo apt autoremove
	sudo apt-get clean
	sudo apt-get autoclean
	#pip install --upgrade pip
	#pip-review --local --interactive
}

reinstall(){
	cd ~/
	mkdir -p tools/__diccionarios
	git clone https://github.com/estebancano-dev/BashAliases.git
	cp ~/BashAliases/.bash_aliases ~/
	rm -R ~/BashAliases 
	git clone https://github.com/estebancano-dev/commonwords.git
	cp ~/commonwords/*.txt ~/tools/__diccionarios
	rm -R ~/commonwords 
	reload
}
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
