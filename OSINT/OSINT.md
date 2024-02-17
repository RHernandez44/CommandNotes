# Google Dorks

  
Go to [Google](https://www.google.com/) and use the search term `**-site:www.tryhackme.com  site:*.tryhackme.com**, `which should reveal a subdomain for tryhackme.com


- `inurl:` Searches for a specified text in all indexed URLs. For example, `inurl:hacking` will fetch all URLs containing the word "hacking".
- `filetype:` Searches for specified file extensions. For example, `filetype:pdf "hacking"` will bring all pdf files containing the word "hacking". 
- `site:` Searches all the indexed URLs for the specified domain. For example, `site:tryhackme.com` will bring all the indexed URLs from  tryhackme.com.
- `cache:` Get the latest cached version by the Google search engine. For example, `cache:tryhackme.com.`

```
whois santagift.shop
```


# CLI Tools

uses database to display public domain info
>https://who.is/

provides sitemap info
`robots.txt 

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

### Sherlock
used to Hunt down social media accounts by username across [social networks](https://github.com/sherlock-project/sherlock/blob/master/sites.md)
`python3 sherlock a_payt --nsfw


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
