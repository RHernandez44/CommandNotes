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

