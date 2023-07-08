import requests
import json
from datetime import datetime
import urllib3
import argparse
import os
import re

import sys
from threading import Thread

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
VER 1.1.1
"""

version = "1.1.1"

changeLog = """
CHANGE LOG
== VER 1.1
- Changed the code's base, added functions etc,
- Added Threads,
- Removed .txt output,
- Fixed issue in HTML file for domain links not present in VirusTotal,
== VER 1.1.1
- Fixed issues in HTML file for AbuseIPDB reporting,
- Added a text when a report is generated at the end of cli output.
"""

print(f"""                                          
 
  _____             _____ _               _             
 |  __ \           / ____| |             | |            
 | |__) |___ _ __ | |    | |__   ___  ___| | _____ _ __ 
 |  _  // _ \ '_ \| |    | '_ \ / _ \/ __| |/ / _ \ '__|
 | | \ \  __/ |_) | |____| | | |  __/ (__|   <  __/ |   
 |_|  \_\___| .__/ \_____|_| |_|\___|\___|_|\_\___|_|   
            | |                                         
            |_|    Version {version}                                    
                                               
 """)

argParser = argparse.ArgumentParser(prog='RepChecker.py',
                    description='Analyze IP Addresses and domains using Virus Total and Abuse IPDB APIs.',
                    epilog='''If you wont input anything, the code will run using the target-list.txt using VirusTotal and AbuseIPDB.
                      You can input domains but they will be only checked on Virus Total because Abuse API does not support domains.''')
argParser.add_argument("-V", "--version", action="store_true", help="Prints current version of the script and exit.", required=False)
argParser.add_argument("-i", "--input", type=str, help="To check single value.", required=False, metavar="[Value]")
argParser.add_argument("-r", "--report", action="store_true", help="Generate HTML report.", required=False)
argParser.add_argument("-vt", "--virustotal", action="store_true", help="Disable virustotal", required=False)
argParser.add_argument("-ab", "--abuse", action="store_true", help="Disable AbuseIPDB", required=False)
argParser.add_argument("-vr", "--virustotalreports", type=int, help="Virustotal malicious reports threshold. Default 1.", required=False, default=1, metavar="[Threshold number]")
argParser.add_argument("-ar", "--abusereports", type=int, help="Abuse IP DB malicious reports threshold. Default 1.", required=False, default=1, metavar="[Threshold number]")
argParser.add_argument("-p", "--path", type=str, help="Provide path of the txt file contains targets. Default 'target-list.txt'.", required=False, default="target-list.txt")
argParser.add_argument("-t", "--threads", type=int, help="Use multiple threads. It is recommended to use it if you have licenced API keys. Also cli output is buggy when used. I recommend using it with -r.", required=False, default=1, metavar="[Threads]")


args = argParser.parse_args()

# INIT GLOBAL PARAMS
htmlReport = []
maliciousValues = []
totalCounter = 0 
successfullyChecked= 0
failedValues = []

if args.version:
    print(f"Current version is {version}")
    print(changeLog)
    exit()

if args.report:
    print("What do you want to call the 'report' HTML file?:")
    reportName = input() + ".html"



ipPattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')


def readFunc(filename):
    output = []
    with open(filename, 'r') as f:
        for line in f:
            output.append(line.strip())
    return output

# ABUSE FUNC
def checkAbuse(value, counter):
    try:
        if ipPattern.search(value):

            abuse_url = 'https://api.abuseipdb.com/api/v2/check'

            querystring = {
                'ipAddress': value,
                'maxAgeInDays': '90'
            }
            abuse_headers = {
                'Accept': 'application/json',
                'Key': abuseApiKeys[counter % len(abuseApiKeys)]
            }

            abuse_response = requests.request(method='GET', url=abuse_url, headers=abuse_headers, params=querystring,
                                                    verify=False)
            decodedResponse = json.loads(abuse_response.text)

            ispName = decodedResponse['data']['isp']
            reportScore = decodedResponse['data']['abuseConfidenceScore']
            reportCount = decodedResponse['data']['totalReports']
            usageType = decodedResponse['data']['usageType']
        else:
            ispName, usageType = ("Can only check valid IP addresses on AbuseIPDB", "Can only check valid IP addresses on AbuseIPDB")
            reportCount, reportScore= (0, 0)
            returnJson = {
            "ispName" : "Can only check valid IP addresses on AbuseIPDB",
            "reportScore" : 0,
            "reportCount" : 0,
            "usageType" : "Can only check valid IP addresses on AbuseIPDB",
            "error" : True
                }
            return(returnJson)

        returnJson = {
            "ispName" : ispName,
            "reportScore" : reportScore,
            "reportCount" : reportCount,
            "usageType" : usageType,
            "error" : False
        }
        return(returnJson)
    except:
        returnJson = {
            "ispName" : "error",
            "reportScore" : 0,
            "reportCount" : 0,
            "usageType" : "error",
            "error" : True
        }
        return(returnJson)

# VIRUS TOTAL FUNC
def checkVirustotal(value, counter):
    try:
        if ipPattern.search(value):
            vtBaseUrl = "https://www.virustotal.com/api/v3/ip_addresses/"
        else:
            vtBaseUrl = "https://www.virustotal.com/api/v3/domains/"
        
        url = f"{vtBaseUrl}{value}"  # VT

        headers = {
            "accept": "application/json",
            "x-apikey": virustotalApiKeys[counter % len(virustotalApiKeys)]
        }

        response = requests.get(url, headers=headers, verify=False)
        json_file = json.loads(response.text)

        try:
            asOwner = json_file["data"]["attributes"]["as_owner"]
        except:
            asOwner = "None"
        lastAnalysisStats = json_file["data"]["attributes"]["last_analysis_stats"]
        isMalicious = json_file["data"]["attributes"]["last_analysis_stats"]["malicious"]

        returnJson = {
            "asOwner" : asOwner,
            "lastAnalysisStats" : lastAnalysisStats,
            "isMalicious" : isMalicious,
            "error" : False
        }
        
        return(returnJson)
    except:
        returnJson = {
            "asOwner" : "Error",
            "lastAnalysisStats" : {"Error": "Error with VirusTotal"},
            "isMalicious" : 0,
            "error" : True
        }
        return(returnJson)

def checking(value, counter):
    global htmlReport 
    global maliciousValues
    global totalCounter  
    global successfullyChecked
    global failedValues
    
    address = value
    ct = counter
    if not args.virustotal: 
        jsonVirustotal = checkVirustotal(address, ct)
        # VT VALUES
        asOwner = jsonVirustotal["asOwner"]
        lastAnalysisStats = jsonVirustotal["lastAnalysisStats"]
        isMalicious = jsonVirustotal["isMalicious"]
        vtError = jsonVirustotal["error"]
        print("\n==Virus Total=="+ ("=" * 35) + "\nAddress:" + address)
        print(f"\tAS Owner: {asOwner}")
        print("\tLast Analysis Stats:")
        for engine, result in lastAnalysisStats.items():
            if isinstance(result, dict):
                category = str(result['category'])
                method = str(result['method'])
                print(f"\t\t{engine}: {category} ({method})")
            else:
                print(f"\t\t{engine}: {result}")
    else:
        isMalicious = 0
        vtError = False
    if not args.abuse:
        jsonAbuse = checkAbuse(address, ct)
        # ABUSE VALUES
        ispName = jsonAbuse["ispName"]
        reportScore = jsonAbuse["reportScore"]
        reportCount = jsonAbuse["reportCount"]
        usageType = jsonAbuse["usageType"]
        abuseError = jsonAbuse["error"]
        print("==Abuse IP DB==" + ("=" *35) + "\nAddress:" + address + "\n\tISP Name: " + ispName + "\n\tAbuse Score: " + str(
                reportScore) + "\n\tReport Counts: " + str(reportCount) + "\n\tUsage Type: " + str(usageType))
    else:
        reportScore = 0
        reportCount = 0
        abuseError = False
        usageType = "NotChecked"

    #print("=" * 50)
    
    # APPEND isMalicious LIST
    if (int(isMalicious) >= args.virustotalreports or int(reportCount) >= args.abusereports or reportScore == 100) and usageType != "Reserved":
        maliciousValues.append(address)
    
    
    # CREATE HTML TABLE ROWS
    if args.report:
        startHtml = f'''
                <table border="1">
        '''
        endHtml = f'''
            </table>
        '''
            
        if not args.virustotal:
            
            vtHtml = f'''
                        <tr>
                            <th colspan="2">Address: {address}</th>
                        </tr>
                        <tr>
                            <td colspan="2" align="center"><strong><a href="https://www.virustotal.com/gui/search/{address}" target="_blank">Virus Total</a></strong></td>
                        </tr>
                        <tr>
                            <td>AS Owner:</td>
                            <td>{asOwner}</td>
                        </tr>
                        <tr>
                            <td>Last Analysis Stats:</td>
                            <td>
                                <table>
                                    {''.join(f'<tr><td>{engine}</td><td>{result["category"]}</td></tr>' if isinstance(result, dict) else f'<tr><td>{engine}</td><td>{result}</td></tr>' for engine, result in lastAnalysisStats.items())}
                                </table>
                            </td>
                        </tr>
                        '''
            startHtml = startHtml + vtHtml

        if not args.abuse:    
            abuseHtml = f'''            
                        <tr>
                            <td colspan="2" align="center"><strong><a href="https://www.abuseipdb.com/check/{address}" target="_blank">Abuse IP DB</a></strong></td>
                        </tr>
                        <tr>
                            <td><b>Address:</b></td>
                            <td><b>{address}</b></td>
                        </tr>
                        <tr> 
                            <td>ISP Name:</td>
                            <td>{ispName}</td>
                        </tr>
                        <tr>
                            <td>Abuse Score:</td>
                            <td>{reportScore}</td>
                        </tr>
                        <tr>
                            <td>Report Counts:</td>
                            <td>{reportCount}</td>
                        </tr>
                        <tr>
                            <td>Usage Type:</td>
                            <td>{usageType}</td>
                        </tr>
                    '''
            startHtml = startHtml + abuseHtml

        startHtml = startHtml + endHtml
        htmlReport.append(startHtml)
    
    if abuseError == True or vtError == True:
        failedValues.append(address)
    else:
        successfullyChecked = successfullyChecked + 1
    
    #totalCounter = totalCounter + 1


if __name__ == "__main__":
    
    # Control which APIs to use
    if args.virustotal and args.abuse:
        print("Not using any APIs, exitting...")
        exit() # Exit if user disabled both
    if args.virustotal is False:
        virustotalApiKeys = list(set(readFunc('api-keys\\vt-apikeys.txt'))) # Get vt api keys
    if args.abuse is False:
        abuseApiKeys = list(set(readFunc('api-keys\\abuse-apikeys.txt'))) # Get abuse api keys

    # INIT COUNTERS


    # GET VALUES
    if args.input is not None:
        print("Analyzing value: " + args.input)
        checkList = []
        checkList += [args.input]
    else:
        checkList = list(set(readFunc(args.path)))


    # START CHECKING THE VALUES
    # Number of threads specified by the user
    num_threads = args.threads
    
    threads = []
    for value in checkList:
        t = Thread(target=checking, args=(value, totalCounter))
        t.start()
        threads.append(t)
        totalCounter += 1

        # Limit the number of active threads based on the user's input
        if len(threads) >= num_threads:
            # Wait for the active threads to finish before creating new ones
            for thread in threads:
                thread.join()
            threads = []

    # Wait for any remaining threads to finish
    for thread in threads:
        thread.join()

    # END OF CHECKING 
    if args.report:
        now = datetime.now()
        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
        with open(reportName, 'w') as html_file:
            html_css = '''
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }

        th, td {
            padding: 8px;
            text-align: left;
            border: 1px solid #ddd;
        }

        th {
            background-color: #f2f2f2;
        }

        td[colspan="2"] {
            text-align: center;
            font-weight: bold;
        }

        a {
            text-decoration: none;
        }
    </style>
    </head>
    <body>
    '''
            html_file.write( f"<h1>RepChecker Report</h1><h3>Issued on {formatted_time}</h3><h4>Successfully checked on {successfullyChecked} values out of {totalCounter}!</h4><h5> Arguments issued: {sys.argv}</h5>")
            html_file.write(html_css)
            for ip_html in htmlReport:
                html_file.write(ip_html)

            html_file.write(f"<table><br><tr><td><h4>Malicious Values</h4> (at least {str(args.virustotalreports)} reported on Virus Total or {str(args.abusereports)} on AbuseIPDB)</td></tr>")        
            for i in maliciousValues:
                html_file.write("<tr><td>%s</td></tr></body>" % i)
            html_file.write('</table></body>\n</html>')

            if failedValues:
                html_file.write('<table><br><tr><td><h4>Failed Values</h4></td></tr>')        
                for i in failedValues:
                    html_file.write("<tr><td>%s</td></tr></body>" % i)
                html_file.write('</table></body>\n</html>')
            html_file.write(f'Version {version}')

    print("=" * 50)
    print(f"\nMalicious Values are: (at least {str(args.virustotalreports)} reported on Virus Total or {str(args.abusereports)} on AbuseIPDB)\n")
    for i in maliciousValues:
        print("%s" % i)

    print(f"Successfully checked on {successfullyChecked} values out of {totalCounter}\n")

    print("Failed Values Are:\n")
    for i in failedValues:
        print("%s" % i)

    if args.report:
        print("\nOutput is also created as " + reportName + " in same directory")
