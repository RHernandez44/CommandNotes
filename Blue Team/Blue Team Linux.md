```shell-session
sudo ufw status verbose
```
Shows Ubuntu default firewall status
```shell-session
sudo ufw default allow outgoing
```
allows all outgoing connections
```shell-session
sudo ufw default deny incoming
```
denies all incoming connections
```shell-session
sudo ufw  allow 22/tcp
```
Allows incoming connections to port22
```shell-session
sudo ufw deny from 192.168.100.25
```
Denies any traffick from IP
```
sudo ufw deny in on eth0 from
192.168.100.26
```
Denies eth0 traffic from IP
```shell-session
sudo ufw reset
```
resets FW rules

# HoneyPots

**PenTBox** is a tool used to set up honeypots
https://github.com/technicaldada/pentbox

# Malware Detection

## Nmap

https://securitytrails.com/blog/nmap-vulnerability-scan

A common malware scan can be performed by using:
`nmap -sV --script=http-malware-host 192.168.1.105`
Or using Google’s Malware check:
`nmap -p80 --script http-google-malware infectedsite.com`

Output example:
`80/tcp open  http |_http-google-malware.nse: Host is known for distributing malware.

### Vulnscan 
The following commands will install the vulscan script along with all the databases mentioned:
```
git clone https://github.com/scipag/vulscan scipag_vulscan
ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan
```
Now let’s perform an Nmap scan for vulnerabilities with vulscan, by using the following syntax:
`nmap -sV --script=vulscan/vulscan.nse www.example.com

### network monitoring and analysis tools
```
Wireshark, 
tshark, 
tcpdump
```



# Firewalls

An intrusion detection system (IDS) inspects network packets for select behavioural patterns or specific content signatures. It raises an alert whenever a malicious rule is met. 

In addition to the IP header and transport layer header, an IDS would inspect the data contents in the transport layer and check if it matches any malicious patterns. 

Depending on the type of firewall/IDS, you might benefit from dividing the packet into smaller packets.

# Create Windows Login Message

- Right-click **Start**, and select **Windows PowerShell (Admin)**. At the UAC prompt, select **Yes**.
    
-  Enter the following code into the _Administrator: Windows PowerShell_ console:
    
    > Be sure to press **Enter** on your keyboard after each entry fully appears in the PowerShell console. There will not be any confirmation.

``` powershell
$BannerText = "This computer system is the property of Structureality Inc. It is for authorized use only. By using this system, all users acknowledge notice of and agree to comply with the Acceptable Use Policy (AUP). Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions set forth in the AUP. By continuing to use this system, you indicate your awareness of and consent to these terms and conditions. If you are physically located in the European Union, you may have additional rights per the GDPR. Visit the website gdpr-info.eu for more information."
```

``` powershell 
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "Authorized Use Only" -PropertyType "String" -Force | Out-Null
```

``` powershell    
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value $BannerText -PropertyType "String" -Force | Out-Null
```

