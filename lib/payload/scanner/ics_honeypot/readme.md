### ICS Detector
##### Research Credits: [Mohammad Reza Zamiri](mailto:mr.zamiri@ieee.org) & Ali Razmjoo Qalaei

+ **This section is under develop to be more flexible with framework, for now you can use it following these steps...**
+ First, run `ics.py` with an IP list or masscan XML output. 
  * `python ics.py -i list.txt` or `python ics.py -i massscan.xml -o real1.json`
+ Second, run scan again after a few hours/moment, save it to other file (e.g. `real2.json`)
+ Third, compare the first scan and second scan result using `changes_percentage.py`

#### Example
```
C:\Users\Zombie\Documents\GitHub\ICS-Detector>python ics.py -i real_device_list.txt -o real1.json
[+] possible found honeypot 151.196.61.241
[+] possible found honeypot 23.25.187.217
[+] possible found honeypot 50.50.14.144
[+] possible found honeypot 216.106.69.169
[+] possible found honeypot 69.34.110.24
[+] possible found honeypot 162.238.14.65
[+] possible found honeypot 50.73.115.174
[+] possible found honeypot 71.245.117.38
[+] possible found honeypot 207.148.206.78
[+] possible found honeypot 173.163.34.33
[+] possible found honeypot 98.235.48.249
[+] possible found honeypot 166.251.229.23
[+] 12/15 possible honeypot founds

C:\Users\Zombie\Documents\GitHub\ICS-Detector>python ics.py -i honeypot_device_list.txt -o fake1.json
[+] possible found honeypot 178.62.58.219
[+] possible found honeypot 165.227.224.226
[+] possible found honeypot 188.226.166.14
[+] possible found honeypot 138.197.169.238
[+] possible found honeypot 146.185.158.34
[+] possible found honeypot 198.199.105.28
[+] possible found honeypot 107.170.224.108
[+] possible found honeypot 159.89.167.21
[+] possible found honeypot 46.101.96.162
[+] possible found honeypot 207.154.215.131
[+] possible found honeypot 167.99.64.194
[+] possible found honeypot 203.217.19.24
[+] 12/17 possible honeypot founds

C:\Users\Zombie\Documents\GitHub\ICS-Detector>python ics.py -i real_device_list.txt -o real2.json
[+] possible found honeypot 151.196.61.241
[+] possible found honeypot 23.25.187.217
[+] possible found honeypot 216.106.69.169
[+] possible found honeypot 50.50.14.144
[+] possible found honeypot 162.238.14.65
[+] possible found honeypot 71.245.117.38
[+] possible found honeypot 50.73.115.174
[+] possible found honeypot 207.148.206.78
[+] possible found honeypot 69.34.110.24
[+] possible found honeypot 173.163.34.33
[+] possible found honeypot 98.235.48.249
[+] possible found honeypot 166.251.229.23
[+] 12/15 possible honeypot founds

C:\Users\Zombie\Documents\GitHub\ICS-Detector>python ics.py -i honeypot_device_list.txt -o fake2.json
[+] possible found honeypot 165.227.224.226
[+] possible found honeypot 178.62.58.219
[+] possible found honeypot 188.226.166.14
[+] possible found honeypot 146.185.158.34
[+] possible found honeypot 46.101.96.162
[+] possible found honeypot 207.154.215.131
[+] possible found honeypot 138.197.169.238
[+] possible found honeypot 107.170.224.108
[+] possible found honeypot 198.199.105.28
[+] possible found honeypot 159.89.167.21
[+] possible found honeypot 167.99.64.194
[+] possible found honeypot 203.217.19.24
[+] 12/17 possible honeypot founds

C:\Users\Zombie\Documents\GitHub\ICS-Detector>python changes_percentage.py real1.json real2.json
HOST:173.163.34.33      CHANGE PERCENTAGE:2.35294117647%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:50.50.14.144       CHANGE PERCENTAGE:2.22222222222%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:98.235.48.249      CHANGE PERCENTAGE:8.19672131148%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:50.73.115.174      CHANGE PERCENTAGE:6.0%  DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:166.251.229.23     CHANGE PERCENTAGE:3.22580645161%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:207.148.206.78     CHANGE PERCENTAGE:6.52173913043%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:23.25.187.217      CHANGE PERCENTAGE:7.04225352113%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:162.238.14.65      CHANGE PERCENTAGE:5.66037735849%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:151.196.61.241     CHANGE PERCENTAGE:2.04081632653%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:216.106.69.169     CHANGE PERCENTAGE:4.0%  DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:71.245.117.38      CHANGE PERCENTAGE:15.5172413793%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False
HOST:69.34.110.24       CHANGE PERCENTAGE:3.1746031746% DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:False  I30100 TRAP:False

C:\Users\Zombie\Documents\GitHub\ICS-Detector>python changes_percentage.py fake1.json fake2.json
HOST:198.199.105.28     CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:146.185.158.34     CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:188.226.166.14     CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:159.89.167.21      CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:178.62.58.219      CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:165.227.224.226    CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:46.101.96.162      CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:107.170.224.108    CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:167.99.64.194      CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:207.154.215.131    CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:138.197.169.238    CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True
HOST:203.217.19.24      CHANGE PERCENTAGE:10.4166666667%        DEFAULT SIGNATURES:False        DEFAULT PRODUCTS:True   I30100 TRAP:True

C:\Users\Zombie\Documents\GitHub\ICS-Detector>
```
  
