# BashAliases
Check wiki for more info

Bash Aliases for Kali Linux
Shortcut to some useful commands for Pentesting or BugBountyHunt.

First time install:

git clone https://github.com/estebancano-dev/BashAliases.git
copy .bash_aliases in ~/ dir
To update with last changes execute this alias:

reinstall This will download last .bash_aliases and commonwords.txt dictionary
Available aliases:

subdomains
Given a domain name, scans for subdomains, tries to resolve them, shows web services, check for alive ones and makes portscan
Tools Used: assetfinder, subfinder, sublist3r, amass, massdns, httprobe, nmap, masscan

usage: subdomains example.com

results: a folder in ~/tools/recon/example.com/date/ with several txt files

1scrapexample.com.txt: all domains and subdomains found scrapping
2massdnsexample.com: massdns test results for all domain and subdomains
3nmapexample.com.txt: nmap test results for alive hosts
4nmapipsexample.com.txt: nmap test results top 100 ports of alive hosts
5masscanexample.com.txt: masscan test results for lot of ports
6httprobeexample.com.txt: httprobe test results (http or https service enabled)
7nmapvulnexample.com.txt: nmap test results for --script vuln
8massdnssimpleexample.com.txt: massdns test result with simple formatting
