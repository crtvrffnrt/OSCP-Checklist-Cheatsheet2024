# Penetration Testing Checklists & Cheat Sheets

A collection of organized checklists and cheat sheets for penetration testing, particularly helpful for the Offsec PEN-200 Exam (OSCP).

---

## Table of Contents

- [Command Cheat Sheets](#command-cheat-sheets)
- [General Checklists](#general-checklists)
- [Web-Application Pre-Authentication Checklist](#web-application-pre-authentication-checklist)
- [Web-Application Directory Enumeration Checklist](#web-application-directory-enumeration-checklist)
- [Web-Application Login Checklist](#web-application-login-checklist)
- [Finding Vulnerabilities and Exploits Checklist](#finding-vulnerabilities-and-exploits-checklist)
- [Network Discovery and Portscan Checklist](#network-discovery-and-portscan-checklist)
- [Active Directory General Checklist](#active-directory-general-checklist)
- [Active Directory with Credentials Checklist](#active-directory-with-credentials-checklist)
- [Active Directory without Credentials Checklist](#active-directory-without-credentials-checklist)
- [Active Directory Kerberos Checklist](#active-directory-kerberos-checklist)
- [Active Directory Lateral and Vertical Movement Checklist](#active-directory-lateral-and-vertical-movement-checklist)
- [Privilege Escalation Windows Checklist](#privilege-escalation-windows-checklist)
- [Privilege Escalation Linux Checklist](#privilege-escalation-linux-checklist)
- [Ligolo-ng Checklist](#ligolo-ng-checklist)

---

## Command Cheat Sheets

### Full TTY Setup
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ls='ls -arlht --color=auto'
stty columns 200 rows 200
```
