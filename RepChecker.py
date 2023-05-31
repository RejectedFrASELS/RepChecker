import requests
import json
from datetime import datetime
import urllib3
import argparse
import os
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
VER 1.0
"""

version = "1.0"

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
                    epilog='''If you wont input anything, the code will run using the target-list.txt and ask you to enter a report name.
                      You can input domains but they will be only checked on Virus Total because Abuse API does not support domains.''')
argParser.add_argument("-V", "--version", action="store_true", help="Prints current version of the script and exit.", required=False)
argParser.add_argument("-i", "--input", type=str, help="To check single value.", required=False)
argParser.add_argument("-r", "--report", action="store_true", help="Generate HTML report.", required=False)
argParser.add_argument("-c", "--cli", action="store_true", help="Output only on console.", required=False)
argParser.add_argument("-vt", "--virustotal", type=int, help="Virustotal malicious reports threshold. Default 1.", required=False, default=1, metavar="[Threshhold number]")
argParser.add_argument("-ab", "--abuse", type=int, help="Abuse IP DB malicious reports threshold. Default 1.", required=False, default=1, metavar="[Threshhold number]")
argParser.add_argument("-p", "--path", type=str, help="Provide path of the txt file contains targets. Default 'target-list.txt'.", required=False, default="target-list.txt")

args = argParser.parse_args()

if args.version:
    print(f"Current version is {version}")
    exit()

ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
#domain_pattern = re.compile(r'^(?:[_a-z0-9](?:[_a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)?$')

iplist = open(args.path, "r")

# reading  file
data = iplist.read()

# replacing end splitting the text
# when newline ('\n') is seen.
check_list = data.split("\n")
iplist.close()

no_duplicated_check_list = list(set(check_list))  # no duplicated ips

if args.input is not None:
    print("Analyzing IP Address: " + args.input)
    no_duplicated_check_list.clear()
    no_duplicated_check_list += [args.input]

# Determine the output txt file's name
if not args.cli:
    print("What do you want to call the output files?:")
    output_name = input()
    output_txt = output_name + ".txt"
    output_html = output_name + ".html"
elif args.report:
    output_txt = "temp.txt"
    print("What do you want to call the 'report' HTML file?:")
    output_name = input()
    output_html = output_name + ".html"
else:
    output_txt = "temp.txt"

    
print("=" * 50)

now = datetime.now()
formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")

filename = 'api-keys\\vt-apikeys.txt'  
api_keys = []

abuse_filename = 'api-keys\\abuse-apikeys.txt'
abuse_api_keys = []

with open(filename, 'r') as f:
    for line in f:
        api_keys.append(line.strip())

with open(abuse_filename, 'r') as f:
    for line in f:
        abuse_api_keys.append(line.strip())

counter = 0
successfully_checked= 0

malicious_list = []
html_report = []
failed_list = []
# Open the output file
with open(output_txt, 'w') as output_file:
    # Use the values in a for loop
    output_file.write(f"Scan started at {formatted_time} \n")
    output_file.write("=" * 50 + "\n")

    for value in no_duplicated_check_list:
        check_abuse = True
        if ip_pattern.search(value):
            base_url = "https://www.virustotal.com/api/v3/ip_addresses/"
        else:
            base_url = "https://www.virustotal.com/api/v3/domains/"
            check_abuse = False
        
        abuse_url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': value,
            'maxAgeInDays': '90'
        }
        abuse_headers = {
            'Accept': 'application/json',
            'Key': abuse_api_keys[counter % len(abuse_api_keys)]
        }  # ABUSE

        url = f"{base_url}{value}"  # VT

        headers = {
            "accept": "application/json",
            "x-apikey": api_keys[counter % len(api_keys)]
        }

        counter = counter + 1
        #sleep(1)
        try:
            # ABUSE
            if check_abuse == True:
                abuse_response = requests.request(method='GET', url=abuse_url, headers=abuse_headers, params=querystring,
                                                verify=False)
                decodedResponse = json.loads(abuse_response.text)

                ispName = decodedResponse['data']['isp']
                reportScore = decodedResponse['data']['abuseConfidenceScore']
                reportCount = decodedResponse['data']['totalReports']
                usageType = decodedResponse['data']['usageType']
            else:
                ispName, usageType = ("Cannot check domains on Abuse IP DB", "Cannot check domains on Abuse IP DB")
                reportCount, reportScore= (0, 0)
            ###
            # VT
            response = requests.get(url, headers=headers, verify=False)
            json_file = json.loads(response.text)

            ip_address = json_file["data"]["id"]
            try:
                as_owner = json_file["data"]["attributes"]["as_owner"]
            except:
                as_owner = "None"
            last_analysis_stats = json_file["data"]["attributes"]["last_analysis_stats"]
            is_malicious = json_file["data"]["attributes"]["last_analysis_stats"]["malicious"]

            if (int(is_malicious) >= args.virustotal or int(reportCount) >= args.abuse or reportScore == 100) and usageType != "Reserved":
                malicious_list.append(value)

            print(f"Address: {ip_address}\n==Virus Total==")
            print(f"\tAS Owner: {as_owner}")
            print("\tLast Analysis Stats:")
            for engine, result in last_analysis_stats.items():
                if isinstance(result, dict):
                    category = str(result['category'])
                    method = str(result['method'])
                    print(f"\t\t{engine}: {category} ({method})")
                else:
                    print(f"\t\t{engine}: {result}")
            print("==Abuse IP DB==\n" + "\tISP Name: " + ispName + "\n\tAbuse Score: " + str(
                reportScore) + "\n\tReport Counts: " + str(reportCount) + "\n\tUsage Type: " + str(usageType))
            print("=" * 50)

            output_file.write(f"Address: {ip_address}\n==Virus Total==\n")
            output_file.write(f"\tAS Owner: {as_owner}\n")
            output_file.write("\tLast Analysis Stats:\n")
            for engine, result in last_analysis_stats.items():
                if isinstance(result, dict):
                    category = str(result['category'])
                    method = str(result['method'])
                    output_file.write(f"\t\t{engine}: {category} ({method})\n")
                else:
                    output_file.write(f"\t\t{engine}: {result}\n")
            output_file.write(
                "==Abuse IP DB==\n" + "\tISP Name: " + ispName + "\n\tAbuse Score: " + str(reportScore) + "\n\tReport Counts: " + str(
                    reportCount) + "\n\tUsage Type: " + str(usageType) + "\n")
            output_file.write("=" * 50 + "\n")

            # Create HTML table for IP address record
            ip_html = f'''
            <table border="1">
                <tr>
                    <th colspan="2">Address: {ip_address}</th>
                </tr>
                <tr>
                    <td colspan="2" align="center"><strong><a href="https://www.virustotal.com/gui/ip-address/{ip_address}" target="_blank">Virus Total</a></strong></td>
                </tr>
                <tr>
                    <td>AS Owner:</td>
                    <td>{as_owner}</td>
                </tr>
                <tr>
                    <td>Last Analysis Stats:</td>
                    <td>
                        <table>
                            {''.join(f'<tr><td>{engine}</td><td>{result["category"]}</td></tr>' if isinstance(result, dict) else f'<tr><td>{engine}</td><td>{result}</td></tr>' for engine, result in last_analysis_stats.items())}
                        </table>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" align="center"><strong><a href="https://www.abuseipdb.com/check/{ip_address}" target="_blank">Abuse IP DB</a></strong></td>
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
            </table>
            '''
            html_report.append(ip_html)
            successfully_checked = successfully_checked + 1
        except Exception as e:
            output_file.write("error with value=" + value + "\n")
            output_file.write("=" * 50 + "\n")
            print("error with value=" + value + "\n")
            print(e)
            failed_list.append(value)
            print("=" * 50 + "\n")

# Generate HTML report if specified
if args.report:
    now = datetime.now()
    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
    with open(output_html, 'w') as html_file:
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
        html_file.write( f"<h1>RepChecker Report</h1><h3>Issued on {formatted_time}</h3><h4>Successfully checked on {successfully_checked} values out of {counter}!</h4>")
        html_file.write(html_css)
        for ip_html in html_report:
            html_file.write(ip_html)

        html_file.write(f"<table><br><tr><td><h4>Malicious Values</h4> (at least {str(args.virustotal)} reported on Virus Total and {str(args.abuse)} on AbuseIPDB)</td></tr>")        
        for i in malicious_list:
            html_file.write("<tr><td>%s</td></tr></body>" % i)
        html_file.write('</table></body>\n</html>')

        if failed_list:
            html_file.write('<table><br><tr><td><h4>Failed Values</h4></td></tr>')        
            for i in failed_list:
                html_file.write("<tr><td>%s</td></tr></body>" % i)
            html_file.write('</table></body>\n</html>')
            html_file.write(f'Version {version}')

print(f"Malicious Values are: (at least {str(args.virustotal)} reported on Virus Total and {str(args.abuse)} on AbuseIPDB)\n")
for i in malicious_list:
    print("%s \n" % i)

print(f"Successfully checked on {successfully_checked} values out of {counter}\n")

with open(output_txt, 'a') as output_file:
    output_file.write(f"Malicious Values are: (at least {str(args.virustotal)} reported on Virus Total and {str(args.abuse)} on AbuseIPDB)\n")
    for i in malicious_list:
        output_file.write("%s\n" % i)
    output_file.write(f"Successfully checked on {successfully_checked} values out of {counter}\n")

if failed_list:
    print("Failed values are:\n")
    for i in failed_list:
        print("%s \n" % i)
    with open(output_txt, 'a') as output_file:
        output_file.write("Failed values are:\n")
        for i in failed_list:
            output_file.write("%s\n" % i)


if args.cli and os.path.exists("temp.txt"):
    os.remove("temp.txt")
else:
    print("\nThe output is also created as " + output_txt + " in the same directory.")

x = input("\nPress 'Enter' to exit")
