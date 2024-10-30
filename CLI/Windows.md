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

```powershell
icacls .\comptia-logo.jpg     
```
Views the permissions currently assigned to this file.

---
# Users

1. Create the new account by entering the following:
```cmd
net user pat Password1 /add
```

--- 
# SMB Shares

- Enter the following command to create a new share:
```-nocolor
New-SmbShare -Name "LABFILES" -Path "C:\LABFILES" -Description "Share for LABFILES"
```
 Enter the following command to view the current shares:
 ```
Get-SMBShare
```

---
# Powershell Active Directory

- Enter the following command to l- Enter the following command to load the PowerShell module needed to interact with Active Directory:
    
    ```-nocolor
    Import-Module ActiveDirectory
    ```
    
-  Enter the following command to display the current password policy for the domain:
    
    ```-nocolor
    Get-ADDefaultDomainPasswordPolicy
    ```oad the PowerShell module needed to interact with Active Directory:
    
    ```-nocolor
    Import-Module ActiveDirectory
    ```
    
-  Enter the following command to display the current password policy for the domain:
    
    ```-nocolor
    Get-ADDefaultDomainPasswordPolicy
    ```

---

# Encrypted files

To view the encryption status of the objects in the current working folder, run the command:
```-notab-nocolor
cipher
```
Decrypt Jan-Security.txt by running the command:
```-notab-nocolor
cipher /d Jan-Security.txt
```

---
# Docker
To list all available images, in PowerShell, run 
`docker images`
Enter `Docker ps -a` to see a list of the current containers

