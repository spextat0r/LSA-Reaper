sudo apt-get update
sudo apt-get install python3-apt -y
sudo apt-get install samba -y
sudo apt-get install mono-complete -y
sudo apt-get install mingw-w64 -y
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

