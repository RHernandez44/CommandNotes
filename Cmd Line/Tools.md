# Enumeration

Search engines can reveal a lot about internet-accessible servers and devices. You can use special search operators on Google to find hidden info, or use a specialized search engine like Shodan or Censys.

`Dnsenum` is a DNS harvesting tool that can be used to locate all DNS servers and records for an organization.

`TheHarvester` is an enumeration tool that gathers email accounts, employee names, and other contact information related to people.

`Maltego` 
`Recon-NG` are broad-spectrum tools that can gather a wide variety of OSINT.

`Sn1per`
an automated scanner and exploitation tool which performs OSINT recon, port enumeration, vulnerability scanning, and exploits with minimal human interaction.

`Steghide`
`sudo apt-get install steghide`
Ubuntu steganography app

`captcha22`
CAPTCHA cracker 
(requires training data for ML)
https://github.com/WithSecureLabs/captcha22

network monitoring and analysis tools
```
Wireshark, 
tshark, 
tcpdump
```

---

`SiLK` 
helps analysts gain insight into multiple aspects of network behaviour.
```shell-session
rwfileinfo traffic-flows.silk
```
overviewing the file info
`Rwcut`
reads binary flow records and prints those selected by the user in text format
```shell-session
rwfilter suspicious-flows.silk --proto=17 --pass=stdout | rwcut --fields=protocol,sIP,sPort,dIP,dPort --num-recs=5
```
This command filters all UDP records with rwfilter, passes the output to rwcut and displays the first five records with rwcut.
- `rwstats FILENAME --fields=dPort --values=records,packets,bytes,sIP-Distinct,dIP-Distinct --count=10`
    - `--count`: Limits the number of records printed on the console
    - `--values=records,packets,bytes`: Shows the measurement in flows, packets, and bytes
    - `--values=sIP-Distinct,dIP-Distinct`: Shows the number of unique IP addresses that used the filtered field
`rwstats FILENAME --fields=sIP --values=bytes --count=10 --top`
lists the top talkers on the network
`rwfilter FILENAME --aport=53 --pass=stdout | rwstats --fields=sIP,dIP --values=records,bytes,packets --count=10`


---
