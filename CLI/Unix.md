# Navigate

allows us to execute commands in the background	`e.g cp file.txt filecopy.txt &`
`&

to make a list of commands to run
e.g. `sudo apt update && sudo apt-get install whois`
`&&

switch user to user2
`su user2

"." denotes the current working directory
"." before a filename is how *nix denotes hidden files in its structure
`./

escape character - escapes the next character from stdin
`/`

prints file content to stdout
`file [filename]

redirects stderr to Null
`2>/dev/null

makes directory in /tmp with random name
`mktemp -d

displays file space usage
`du

backgrounds the current process
`Ctrl+z

foregrounds current process
`fg


---

# File Direction

## Find

`find / -perm -u=s -type f 2>/dev/null

- `find - Initiates the "find" command  
- `/` - Searches the whole file system  
- `-perm` - searches for files with specific permissions  
- `-u=s` - Any of the permission bits _mode_ are set for the file. Symbolic modes are accepted in this form
- `-type f**` - Only search for files  
- `2>/dev/null - Suppresses errors

prints list > then pipes that to file
`ls | file -f -
displays location of file
`which [filename]

`grep
searches for patterns
- -i ignores case
- -v inverts search case (ignore everything with [pattern]
- -n prints what line number is beside each grep
- -A 2 -B 4  -- prints the 2 lines AFTER and 4 lines BEFORE

grep a file
`grep "ftp" /usr/share/nmap/scripts/script.db
-E	Searches using regex (regular expressions). For example, we can search for lines that contain either "thm" or "tryhackme"	
`grep -E "thm|tryhackme" log.txt
Search recursively. For example, search all of the files in a directory for this value.
`grep -r "helloworld" mydirectory

ls a directory for files that contain *ftp*
`ls -l /usr/share/nmap/scripts/*ftp*
sort lines of text files
`sort
displays lines that are repeated
`uniq
finds string patterns in a file
`strings 
only see one field from the password file.
`cut -d:  -f1
For example, to just see the Unix user names, use the command 
` “$ cat /etc/passwd | cut -d: -f1.” 
The nl command stands for **number lines**. It renders the contents of the file in a numbered line format.
`nl access.log

## Log Analysis

cuts into columns delimited by a space ( ' ' ) 
`cut -d ' ' -f1,3,6 access.log
takes columns 1,3 & 6

- The first use of the cut command retrieves the column of the domain:port, and the second one removes the port by splitting it with a colon.

~~~
ubuntu@tryhackme:~/Desktop/artefacts$ cut -d ' ' -f3 access.log | cut -d ':' -f1
sway.com
sway.com
sway.office.com
--- REDACTED FOR BREVITY ---
~~~

-  After retrieving the domains, the sort command arranges the list in alphabetical order

~~~
ubuntu@tryhackme:~/Desktop/artefacts$ cut -d ' ' -f3 access.log | cut -d ':' -f1 | sort
account.activedirectory.windowsazure.com
account.activedirectory.windowsazure.com
account.activedirectory.windowsazure.com
--- REDACTED FOR BREVITY ---
~~~

- Lastly, the uniq command removes all the duplicates

~~~
ubuntu@tryhackme:~/Desktop/artefacts$ cut -d ' ' -f3 access.log | cut -d ':' -f1 | sort | uniq
account.activedirectory.windowsazure.com
activity.windows.com
admin.microsoft.com

--- REDACTED FOR BREVITY ---
~~~


----

# Add HOSTNAME

How to add hostname 
- If you are connected via VPN or AttackBox, you can add the hostname `mcgreedysecretc2.thm` by first opening the host file, depending on your host operating system.  
- Windows                       :  `C:\Windows\System32\drivers\etc\hosts`
- Ubuntu or AttackBox: `/etc/hosts`

- Open the host file and add a new line at the end of the file in the format: `10.10.196.106 mcgreedysecretc2.thm`
- Save the file and type `http://mcgreedysecretc2.thm` in the browser to access the website.

# IP Info

find IP address of a domain name
`nslookup DOMAIN_NAME`
`nslookup OPTIONS DOMAIN_NAME SERVER`
`nslookup -type=a tryhackme.com 1.1.1.1`

`ifconfig`
Unix-like operating systems, displays or configures IP settings for network interfaces.

`netstat`
Displays a variety of network information, including active connections, routing tables, and traffic statistics.

`arp`
Displays the IPv4 ARP cache.

`traceroute`
Views or manipulates the IP routing table used to find paths to network addresses

`nslookup`
Performs DNS lookups and displays the IP address of a given hostname.digA more powerful alternative to nslookup. Particularly useful for zone transfers.

`traceroute`
`tracert`
Displays the hop-by-hop path to a given host, along with the round-trip time to each hop.

# Zip Files

```
xxd -r
```
reverts a hexdump file
```
zcat
bzcat
```
decompresses file to stdout

```
tar
```
collects two or more files into one file using
a format that allows the files to be extracted later
>commonly compressed with gzip, bzip2 into a “tarball”.

```
tar xO
```
extracts tar files


# Cron

`crontab -l
shows cron jobs

https://crontab-generator.org/

holds cronjob info
/etc/crontab

crontabs have the following format:
`<minute> <hour> <day of month> <month> <day of week> <user> <command>`

add .sh file to cron
```bash 
echo "0 1 * * * /bin/bash /root/ip_block.sh" | crontab -
```

# Ps

processes
`ps
displays cpu jobs and pids
`top`
lists all services
`systemctl list-unit-files`
kills the proccess of that PID no#
`kill [PID]


---

# ----Handy Nix FILES----

>`var/log

>`.bashrc

list of users
`>/etc/passwd`

SSH keys stored at 
`>/home/user/.ssh`

list of available shells 
`/etc/shells

holds cronjob info
/etc/crontab

logs access information, ip of logins etc

>`/usr/share/seclists

>`/usr/share/wordlists

>`The ~/.ssh folder is the default place to store these keys for OpenSSH

>`/etc/hosts

>`/etc/passwd

>`password hashes are stored in /etc/shadow

- Modern Linux systems salt password hashes by default. The most common default hashing scheme of Linux is yescrypt. This is confirmed in the output by the "_y_ " between the first two dollar signs. The "_j9T_ " value between the second and third dollar signs are parameters used during the hashing process. The value between the third and fourth dollar signs is the salt used when producing the hash. Then, the value after the fourth dollar sign (until the colon) is the salted password hash.
```
ryan:$y$j9T$h9o1ZcyOA/GMHwdqsE0oc/$kuogrJK0ZvaWfFD7GiUT/slZFxpd49fQMFBLmGmywE9:20019:0:99999:7:::
```

shows logs
>`/var/log

| Category | Description | File | Example |
|---|---|---|---|
|Authentication|This log file contains all authentication (log in). This is usually attempted either remotely or on the system itself (i.e., accessing another user after logging in).|	auth.log|Failed password for root from 192.168.1.35 port 22 ssh2.
|Package Management |This log file contains all events related to package management on the system. When installing a new software (a package), this is logged in this file. This is useful for debugging or reverting changes in case this installation causes unintended behaviour on the system.|dpkg.log|2022-06-03 21:45:59 installed neofetch
|Syslog	|This log file contains all events related to things happening in the system's background. For example, crontabs executing, services starting and stopping, or other automatic behaviours such as log rotation. This file can help debug problems.|syslog|2022-06-03 13:33:7 Finished Daily apt download activities..|
|Kernel|This log file contains all events related to kernel events on the system. For example, changes to the kernel, or output from devices such as networking equipment or physical devices such as USB devices.|	kern.log|2022-06-03 10:10:01 Firewalling registered|


| **Location** | **Description** |
| ---- | ---- |
| /etc/issue | contains a message or system identification to be printed before the login prompt. |
| /etc/profile | controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived |
| /proc/version | specifies the version of the Linux kernel |
| /etc/passwd | has all registered user that has access to a system |
| /etc/shadow | contains information about the system's users' passwords |
| /root/.bash_history | contains the history commands for root user |
| /var/log/dmessage | contains global system messages, including the messages that are logged during system startup |
| /var/mail/root | all emails for root user |
| /root/.ssh/id_rsa | Private SSH keys for a root or any known valid user on the server |
| /var/log/apache2/access.log | the accessed requests for Apache  webserver |
| C:\boot.ini | contains the boot options for computers with BIOS firmware |
`/proc/version`
Since every process has a file in the proc directory, you can retrieve lots of information through this technique. Experiment with the following filenames from the /proc directory:

- cpuinfo
- devices
- locks
- meminfo
- misc
- modules
- uptime


# Common Hash Prefixes

>$1$	    md5crypt, used in Cisco stuff and older Linux/Unix systems
>$2$, $2a$, $2b$, $2x$, $2y$        Bcrypt (Popular for web applications)
>$6$    	sha512crypt (Default for most Linux/Unix systems)

# GPG

```
gpg --import [keyfile]
```

imports secret key

```
gpg --decrypt [FILE_TO_DECRYPT]
```

---
# Connect
```
telnet [ip_address] [port] 
```
```
nc [nameofhost] [port]
```
connects to host

```
openssl s_client -connect [host]:[port] -ign_eof
```
connects to port using ssl encryption

``` 
nc -lvp 4444
```
sets a listener to port 4444

## SSH

```
ssh raz@10.10.169.1
```
~~~
ssh -i [rsa_key_filename] [user]@[ip_address]
~~~
~~~
ssh -i keyNameGoesHere user@host
~~~
how you specify a key for the standard Linux OpenSSH client.
>The ~/.ssh folder is the default place to store these keys for OpenSSH

**ensure you use `chmod 600 rsa_key_filename`**

```
ssh-copy-id -i ~/.ssh/id_rsa.pub YOUR_USER_NAME@IP_ADDRESS_OF_THE_SERVER
```
Your public key should be copied at the appropriate folder on the remote server automatically.


## Connect to MYSQL server

```
mysql -h [IP] -u [username] -p
```

## Remote Desktop - RDP

```
xfreerdp /u:thm-unpriv /p:Password321 /v:10.10.191.159 /dynamic-resolution
```

## FTP

common FTP server host software:
- [vsftpd](https://security.appspot.com/vsftpd.html)
- [ProFTPD](http://www.proftpd.org/)
- [uFTP](https://www.uftpserver.com/)

connect
`ftp frank@10.10.126.132

get files
`get README.txt 

`STAT` can provide some added information.  
`SYST` command shows the System Type of the target (UNIX in this case). 
`PASV` switches the mode to passive. 
- Active: In the active mode, the data is sent over a separate channel originating from the FTP server’s port 20.
- Passive: In the passive mode, the data is sent over a separate channel originating from an FTP client’s port above port number 1023.

 `TYPE A` switches the file transfer mode to ASCII, while 
 `TYPE I` switches the file transfer mode to binary.


## SMTP

1. Simple Mail Transfer Protocol (SMTP)
2. Post Office Protocol version 3 (POP3)
3. Internet Message Access Protocol (IMAP)

connect using telnet 
`telnet 10.10.126.132 25

### POP3
`STAT`, we get the reply `+OK 1 179`;
a positive response to `STAT` has the format `+OK nn mm`, where _nn_ is the number of email messages in the inbox, and _mm_ is the size of the inbox in octets (byte). 
`LIST` provided a list of new messages on the server
`RETR 1` retrieved the first message in the list.

### IMAP 

Internet Message Access Protocol (IMAP) is more sophisticated than POP3. IMAP makes it possible to keep your email synchronized across multiple devices (and mail clients).

MAP requires each command to be preceded by a random string to be able to track the reply. So add `c1`, then `c2`, and so on

`LOGIN username password`
`LIST "" "*"`
`EXAMINE INBOX`


---

# RSA

The key variables that you need to know about for RSA in CTFs are p, q, m, n, e, d, and c.

“p” and “q” are large prime numbers, “n” is the product of p and q.

The public key is n and e, the private key is n and d.

“m” is used to represent the message (in plaintext) and “c” represents the ciphertext (encrypted text).

# REGEX

- [0-9] - Will include numbers 0-9

- [0] - Will include only the number 0

- [A-z] - Will include both upper and lowercase

- [A-Z] - Will include only uppercase letters

- [a-z] - Will include only lowercase letters

- [a] - Will include only a

- [!£$%@] - Will include the symbols !£$%@


# Exit VIM

To save a file and exit Vim, do the following:

- Switch to command mode by pressing the Esc key.
- Press : (colon) to open the prompt bar in the bottom left corner of the window.
- Type x after the colon and hit Enter. This will save the changes and exit.

---
