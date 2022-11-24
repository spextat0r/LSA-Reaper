sudo python3 -m pip install -r requirements.txt
sudo python3 -m pip install pypykatz --upgrade
cd ..
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
sudo python3 setup.py install
