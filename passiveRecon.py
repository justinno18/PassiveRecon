import socket
import re
import json
import whois
import os
import subprocess
from numpy import loadtxt


def do_whois_request(ip, whois_server):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((whois_server, 43))
    s.send((ip + "\r\n").encode())
    response = b""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    return response.decode("utf-8", "ignore")

def do_whois(ip):
    whois_org = ["arin", "lacnic", "afrinic", "ripe", "apnic"]
    whois_server_tpl = "whois.%s.net"
    # First try with ARIN
    whois_response = do_whois_request(ip, whois_server_tpl % "arin")
    for line in whois_response.splitlines():
        if line.strip().startswith("Ref:"):
            # IP block is not managed by ARIN so we call the provided org in the Ref link
            link = line[4:].strip(" ")
            org = link.split("/")[-1]
            if org.lower() in whois_org:
                whois_response = do_whois_request(ip, whois_server_tpl % org)
                break
    return whois_response

#fetching whois data from multiple servers
	
#asking user to input the domain name
domainName = input("Input host domain name: ")
#Converting the domain name to an ip address
IPAddr = socket.gethostbyname(domainName)
#running the whois function defined in the first part of the code
whoisOP = do_whois(IPAddr)
#filtering data
filtered = {}
filters = ['inetnum','netname', 'route']
for filter in filters:
    filtered[filter] = ''.join(line for line in whoisOP.splitlines() if filter in line).strip(filter + ":")
    filtered[filter] = re.sub('\s+', '', filtered[filter])


#joining data from different whois commands
whoisData = whois.whois(domainName) | filtered

#exporting data to a json file.
#with open('./data/whoisData.json', 'w') as fp:
    #json.dump(whoisData, fp, indent=2, sort_keys=True, default=str)


filename = domainName + '.json'

#checking for ssl
print('-------------------Checking for SSL--------------------------')
subprocess.run('python ssl_checker.py -H '+ domainName + ' -J', shell=True, check=True,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print('Success! Data saved')
#loading json data into a dictionnary
with open(filename, 'r') as file:
    SSLdata = json.load(file)

#Running the harvester command
print('-------------------Running the harvester---------------------')
subprocess.run('theHarvester -d' + domainName +' -b all -l 1000 --filename ./data/theharvester' + filename,shell=True, check=True,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print('Success! Data saved')
#loading json data into a dictionnary
with open('./data/theharvester' + filename, 'r') as file:
    theHarvesterdata = json.load(file)

print('Saving data...')
#Formatting all the data in a txr file
textExport = domainName + '.txt'
file = open('./data/findings.txt', 'w')
file.write("List of findings for " + domainName + ":\n")
file.write("\t Whois: \n")
for row, value in whoisData.items():
	if value != None and row != None:
		value = str(value)
		file.write("\t\t" + row + ': ' + value + '\n')

file.write('\n\t SSL: \n')
for row, value in SSLdata.items():
	if value != None and row != None:
		if isinstance(value, str) == 0:
			value = str(value)
		file.write("\t\t" + row + ': ' + value + '\n')
	
file.write('\n\t theHarvester: \n')
for row, value in theHarvesterdata.items():
	if value != None and row != None:
		if isinstance(value, str) == 0:
			value = str(value)
		file.write("\t\t" + row + ': ' + value + '\n')

file.close()
print('Data saved into data/findings.txt')

#removing json files
subprocess.run('rm ' + filename, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#subprocess.run('rm ./data/theharvester' + filename, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)



