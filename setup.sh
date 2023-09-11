sudo apt-get update
sudo apt-get install samba
sudo apt-get install mono-complete
sudo python3 -m pip install -r requirements.txt
sudo python3 -m pip install pypykatz --force-reinstall --upgrade
if [ -d "../impacket" ] 
then
    echo "Impacket is already downloaded" 
else
    cd ..
    sudo git clone https://github.com/fortra/impacket.git
    cd impacket
    sudo python3 setup.py install
fi

