# RepChecker
Checking Bulk IP Addresses and domains' reputation using Virus Total and Abuse IP DB API. Can generate HTML reports.<br>
<br>
To use the script, you need to get Virus Total and Abuse IP DB API keys and paste them into txt files in api-keys folder line by line.<br>
You can use multiple API keys, the code will use them one by one for each value. This will help you maintain the API keys' limits.<br>

**You can use multithreading to run the code faster!**<br>
It is recommended to have licenced API keys and generate an HTML report, CLI output is sometimes buggy with multithreading on<br>

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
            |_|    Version 1.1

 
usage: RepChecker.py [-h] [-V] [-i [Value]] [-r] [-vt] [-ab] [-vr [Threshold number]] [-ar [Threshold number]] [-p PATH] [-t [Threads]]

Analyze IP Addresses and domains using Virus Total and Abuse IPDB APIs.

options:
  -h, --help            show this help message and exit
  -V, --version         Prints current version of the script and exit.
  -i [Value], --input [Value]
                        To check single value.
  -r, --report          Generate HTML report.
  -vt, --virustotal     Disable virustotal
  -ab, --abuse          Disable AbuseIPDB
  -vr [Threshold number], --virustotalreports [Threshold number]
                        Virustotal malicious reports threshold. Default 1.
  -ar [Threshold number], --abusereports [Threshold number]
                        Abuse IP DB malicious reports threshold. Default 1.
  -p PATH, --path PATH  Provide path of the txt file contains targets. Default 'target-list.txt'.
  -t [Threads], --threads [Threads]
                        Use multiple threads. It is recommended to use it if you have licenced API keys. Also cli output is buggy when used. I recommend using it with -r.

If you wont input anything, the code will run using the target-list.txt using VirusTotal and AbuseIPDB. You can input domains but they will be only checked on Virus Total because Abuse API does not support domains.
```
## Example Commands
**Use target-list.txt, output on cli:**
```
RepChecker.py 
```
**Use target-list.txt, create an HTML report. Also filter the Malicious thresholds:**
```
RepChecker.py -r -vr 5 -ar 50 
```
```-r``` is for creating a HTML report, ```-vr 5``` and ```-ar 50``` are to filter 'malicious list' that will be provided in end of the code. This way, the 'malicious list' will only contain the values that are flagged atleast 5 times on VirusTotal and reported 50 times on Abuse IP DB.<br><br>
**Use multithreading and create an HTML report**
```
RepChecker.py -t 16 -r
```
**Provide path to target list, create an HTML report**
```
RepChecker.py -p /PATH/ -r
```
**Check single value, output only on cli**
```
RepChecker.py -i 8.8.8.8
```
**Disable Virustotal checking, to disable AbuseIP you can use the -ab option**
```
RepChecker.py -vt
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
Malicious Values are: (at least 1 reported on Virus Total or 1 on AbuseIPDB)

8.8.8.8

Successfully checked on 1 values out of 1
```
The HTML file report will be like in the following image below:
![repcheckerreport](https://github.com/RejectedFrASELS/RepChecker/assets/121792966/fbf7f39c-5ee9-4eb2-a4b4-60a41cbecc47)


## Roadmap
There are some features I want to add in future. Maybe I won't add at all.
- [x] Adding Multithreading!
- [x] Change the code's base, add functions to each task, beautfiy it. This way the code will be more coder friendly and will be a lot easier to add new features. The reason for this code to be in this sloppy shape is because it started with reading from a txt file and outputting on txt file using only Virus Total API
- [x] Adding option to on-off Abuse IP DB or Virus Total on checks.
- [ ] Adding option to check hashes and other stuff that you can check using Virus Total API.
- [ ] Adding a "config" file to store all configs, letting user to change the configs using cli or text editor.
- [ ] An option to sleep a time interval between values since some firewalls might block the traffic.
- [ ] Detect which API key failed, put it on report. If an API key fails, select the next API key and continue
- [ ] Adding GUI
- [ ] Adding an option to turn of cli output (Verbose)

