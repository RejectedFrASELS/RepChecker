# RepChecker
Checking Bulk IP Addresses and domains using Virus Total and Abuse IP DB API. Can generate HTML reports.<br>
<br>
To use the script, you need to get Virus Total and Abuse IP DB API keys and paste them into txt files in api-keys folder line by line.<br>
You can use multiple API keys, the code will use them one by one for each value. This will help you maintain the API keys' limits.<br><br>

Also you need to have Python 3 and need to install requirements using ```pip install -r requirements.txt```

You can use the script in different ways. I added some values for you to test in 'target-list.txt'<br>

Options included in script:
```
  _____             _____ _               _
 |  __ \           / ____| |             | |
 | |__) |___ _ __ | |    | |__   ___  ___| | _____ _ __
 |  _  // _ \ '_ \| |    | '_ \ / _ \/ __| |/ / _ \ '__|
 | | \ \  __/ |_) | |____| | | |  __/ (__|   <  __/ |
 |_|  \_\___| .__/ \_____|_| |_|\___|\___|_|\_\___|_|
            | |
            |_|    Version 1.0


usage: RepChecker.py [-h] [-V] [-i INPUT] [-r] [-c] [-vt [Threshold number]] [-ab [Threshold number]] [-p PATH]

Analyze IP Addresses and domains using Virus Total and Abuse IPDB APIs.

options:
  -h, --help            show this help message and exit
  -V, --version         Prints current version of the script and exit.
  -i INPUT, --input INPUT
                        To check single value.
  -r, --report          Generate HTML report.
  -c, --cli             Output only on console.
  -vt [Threshold number], --virustotal [Threshold number]
                        Virustotal malicious reports threshold. Default 1.
  -ab [Threshold number], --abuse [Threshold number]
                        Abuse IP DB malicious reports threshold. Default 1.
  -p PATH, --path PATH  Provide path of the txt file contains targets. Default 'target-list.txt'.

If you wont input anything, the code will run using the target-list.txt and ask you to enter a report name. You can
input domains but they will be only checked on Virus Total because Abuse API does not support domains.
```
## Example Commands
**Use target-list.txt, output on cli and create a txt report:**
```
RepChecker.py 
```
**Use target-list.txt, output on cli, create a txt report and HTML report. Also filter the Malicious thresholds:**
```
RepChecker.py -r -vt 5 -ab 50 
```
```-r``` is for creating a HTML report, ```-vt 5``` and ```-ab 50``` are to filter 'malicious list' that will be provided in end of the code. This way, the 'malicious list' will only contain the values that are flagged atleast 5 times on VirusTotal and reported 50 times on Abuse IP DB.<br><br>
**Provide path to target list, output on cli and create a HTML report**
```
RepChecker.py -p /PATH/ -r -c
```
**Check single value, output only on cli**
```
RepChecker.py -i 8.8.8.8 -c
```
## Outputs and Reports
The command-line output of ```RepChecker.py -i 8.8.8.8 -r``` will be like the following:
```
Analyzing IP Address: 8.8.8.8
==================================================
Address: 8.8.8.8
==Virus Total==
        AS Owner: GOOGLE
        Last Analysis Stats:
                harmless: 68
                malicious: 2
                suspicious: 0
                undetected: 17
                timeout: 0
==Abuse IP DB==
        ISP Name: Google LLC
        Abuse Score: 0
        Report Counts: 54
        Usage Type: Data Center/Web Hosting/Transit
==================================================
Malicious Values are: (at least 1 reported on Virus Total and 1 on AbuseIPDB)

8.8.8.8

Successfully checked on 1 values out of 1
```
The same output will be also on the txt file created. <br>
The HTML file report will be like in the following image below:
![image](https://github.com/RejectedFrASELS/RepChecker/assets/121792966/ef23e1cc-dd74-44a8-93ef-ec05f2878564)

## Roadmap
There are some features I want to add in future. Maybe I won't add at all.
1. Change the code's base, add functions to each task, beautfiy it. This way the code will be more coder friendly and will be a lot easier to add new features. The reason for this code to be in this sloppy shape is because it started with reading from a txt file and outputting on txt file using only Virus Total API
2. Adding option to on-off Abuse IP DB or Virus Total on checks.
3. Adding option to check hashes and other stuff that you can check using Virus Total API.
4. Adding a "config" file to store all configs, letting user to change the configs using cli or text editor.
5. An option to sleep a time interval between values since some firewalls might block the traffic.
6. Detect which API key failed, put it on report. If an API key fails, select the next API key and continue

