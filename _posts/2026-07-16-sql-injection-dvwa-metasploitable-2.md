---
title: "SQL Injection Attacks Using DVWA and Metasploitable 2"
date: 2026-07-16 12:00:00 +0800
categories: [Web Security]
tags: [sql-injection, dvwa, metasploitable, nmap, sqlmap, ethical-hacking]
description: "A complete SQL injection attack chain in an isolated DVWA lab, from reconnaissance and manual validation to automated extraction and defensive recommendations."
image:
  path: /assets/img/posts/sql-injection-dvwa/nmap-service-enumeration.jpg
  alt: Nmap service enumeration against the Metasploitable 2 lab target
---

> **Assignment note:** I completed this Ethical Hacking and Incident Response assignment on **May 30, 2026**. I am publishing the practical work here on **July 16, 2026** as a retrospective case study. Every action shown was performed against an intentionally vulnerable machine on an isolated host-only network.
{: .prompt-info }

## Project Brief

This project documented a complete SQL injection attack chain against Damn Vulnerable Web Application (DVWA) running on Metasploitable 2. It was prepared for the APU module **CT080-3-2-EHIR - Ethical Hacking and Incident Response**, taught by **Ts. Mohd Norfahmi Bin Jaafar**. The assignment was issued on April 8, 2026, and had a formal hand-in date of May 31, 2026.

The objective was not simply to run an automated tool. I wanted to reproduce the workflow an ethical hacker should follow: establish a safe lab, identify the target, enumerate its attack surface, prove the vulnerability manually, automate extraction, evaluate the tools, and recommend controls that address the root cause.

## Why SQL Injection Still Matters

Web applications accept user-controlled data, build database queries, generate dynamic content, and execute server-side logic. When an application fails to keep data separate from executable SQL syntax, an attacker can alter the intended query.

A vulnerable lookup might be written as:

```sql
SELECT first_name, last_name
FROM users
WHERE user_id = '$id';
```

A normal value such as `1` returns one record. An input such as `1' OR '1'='1` changes the logic so that the condition is always true:

```sql
SELECT first_name, last_name
FROM users
WHERE user_id = '1' OR '1'='1';
```

That simple change can bypass an application's intended access control and return every row. The broader SQL injection family includes:

- **In-band injection:** error-based or UNION-based extraction returns data through the application's normal response.
- **Inferential injection:** boolean-based or time-based behaviour reveals data without placing it directly in the response body.
- **Out-of-band injection:** the database sends data through another protocol, such as DNS or HTTP, when the normal response channel is unavailable.

Injection remained third in the [OWASP Top 10 for 2021](https://owasp.org/Top10/A03_2021-Injection/). Incidents such as Heartland Payment Systems in 2008 and TalkTalk in 2015 also show the real consequences of unsafe input handling: large-scale data theft, regulatory penalties, and loss of trust.

## Scenario and Scope

The report used a fictional medium-sized e-commerce company to give the exercise a realistic operational context. Its internal application was modelled on a legacy Apache, PHP, and MySQL stack. Customer accounts, orders, and payment records were assumed to sit behind an in-house application whose lookup feature concatenated user input directly into SQL.

The actual technical work did **not** target a real organisation. It used two virtual machines in VMware Workstation:

| Role | System | Address | Resources |
| --- | --- | --- | --- |
| Attacker | Kali Linux | `192.168.142.128` | 4 GB RAM, 2 CPU cores |
| Target | Metasploitable 2 | `192.168.142.133` | 512 MB RAM, 1 CPU core |

Both adapters were attached to the host-only `VMnet0` segment. This allowed the machines to communicate with each other while keeping the deliberately vulnerable target away from the physical network and internet.

![Kali Linux and Metasploitable 2 listed in VMware](/assets/img/posts/sql-injection-dvwa/vmware-lab-machines.png)
_The two machines used in the isolated lab._

![Kali Linux virtual machine configuration](/assets/img/posts/sql-injection-dvwa/kali-vm-configuration.png)
_Kali Linux was allocated 4 GB of RAM, two processor cores, and a host-only adapter._

![Metasploitable 2 virtual machine configuration](/assets/img/posts/sql-injection-dvwa/metasploitable-vm-configuration.png)
_Metasploitable 2 was intentionally kept close to a low-resource legacy server profile._

The target exposed Apache on port 80, MySQL on port 3306, and DVWA under `/dvwa`. The attacker profile was an intermediate threat actor with access to the internal segment and the objective of extracting stored application credentials. No malware, operating-system exploit, or authentication bypass was needed; the attack remained entirely within the application's HTTP interface.

## Tools and Their Roles

### Nmap

Nmap provided host discovery, port scanning, service-version detection, banner collection, operating-system hints, NSE script output, and traceroute data. I used it twice: first for broad service enumeration, then for a focused aggressive scan of port 80.

### Dirb

Dirb sent HTTP requests for candidate paths from `/usr/share/dirb/wordlists/common.txt`. A `200` response indicated an accessible resource, `403` indicated an existing but forbidden resource, and `404` indicated that the resource was absent. Its job was to map the web server without source-code access.

### DVWA

DVWA is a deliberately insecure PHP/MySQL application distributed with Metasploitable 2 for security training. Its security levels progressively change the amount of validation and protection applied. I used **Low**, where the SQL injection module concatenates the `id` parameter without meaningful sanitisation.

### sqlmap

sqlmap automated injection testing, DBMS fingerprinting, database and table enumeration, row extraction, hash identification, and dictionary-based password cracking. It supports boolean-based blind, error-based, time-based blind, UNION query, and stacked-query techniques across several database platforms.

## 1. Building and Verifying the Lab

After booting Metasploitable 2, `ifconfig` confirmed `192.168.142.133` on `eth0`.

![Metasploitable 2 ifconfig output showing 192.168.142.133](/assets/img/posts/sql-injection-dvwa/metasploitable-ifconfig.png)
_The target address assigned on the isolated host-only network._

From Kali, I then checked basic reachability:

```console
ping 192.168.142.133
```

![Kali ping test showing zero packet loss](/assets/img/posts/sql-injection-dvwa/kali-ping-test.jpg)
_Eight replies with zero packet loss confirmed connectivity before scanning._

## 2. Footprinting and Reconnaissance

The first active reconnaissance command combined service-version detection with banner collection:

```console
nmap -sV --script=banner 192.168.142.133
```

The scan exposed more than 20 open TCP ports. The findings that mattered most to this exercise were:

- Apache httpd 2.2.8 on TCP port 80
- MySQL 5.0.51a on TCP port 3306
- PHP as the server-side technology inferred from the Apache stack

![Nmap service and banner enumeration](/assets/img/posts/sql-injection-dvwa/nmap-service-enumeration.jpg)
_The service scan established that the web application and database backend were reachable from the attacker segment._

## 3. Computer and Network Scanning

I narrowed the next Nmap scan to the web service:

```console
nmap -A -p 80 192.168.142.133
```

The `-A` option enabled operating-system detection, version detection, NSE scripts, and traceroute. The result confirmed Apache 2.2.8 on a Linux 2.6.x kernel, returned the title `Metasploitable2 - Linux`, and showed a single hop between both machines.

![Aggressive Nmap scan of port 80](/assets/img/posts/sql-injection-dvwa/nmap-aggressive-port-80.jpg)
_Focused enumeration of the target's HTTP service._

I followed that with directory discovery:

```console
dirb http://192.168.142.133
```

Dirb tested 4,612 candidate names. Among its results were `/dvwa`, which identified the application used for the exploitation phase, and `/phpMyAdmin`, which independently supported the presence of a MySQL backend.

![First section of the Dirb enumeration output](/assets/img/posts/sql-injection-dvwa/dirb-enumeration-part-1.jpg)
_Dirb beginning its enumeration with the default common-word list._

![Second section of the Dirb enumeration output](/assets/img/posts/sql-injection-dvwa/dirb-enumeration-part-2.jpg)
_The discovered web paths included DVWA and phpMyAdmin._

## 4. Manual SQL Injection

I opened `http://192.168.142.133/dvwa`, authenticated with DVWA's default lab credentials, set the security level to **Low**, and used **Create / Reset Database** to initialise the `users` and `guestbook` tables.

![DVWA login page](/assets/img/posts/sql-injection-dvwa/dvwa-login.png)
_Authentication to the intentionally vulnerable training application._

![DVWA configured at the low security level](/assets/img/posts/sql-injection-dvwa/dvwa-low-security.png)
_Low security removed the input protections that this exercise was designed to examine._

![DVWA database setup page](/assets/img/posts/sql-injection-dvwa/dvwa-database-setup.png)
_The laboratory users and guestbook tables were created successfully._

### Establishing a Baseline

Before injecting anything, I submitted `1` to the User ID field. The page returned only the `admin` record, proving that the lookup worked normally and giving me a baseline for comparison.

![DVWA returning the normal record for user ID 1](/assets/img/posts/sql-injection-dvwa/dvwa-baseline-query.png)
_Normal query behaviour returned a single row._

### Boolean-Based Proof

I then submitted:

```sql
1' OR '1'='1
```

The appended expression is always true. DVWA returned all five user records without rejecting the input or displaying a controlled error. This proved that user input was entering the MySQL query as executable syntax.

![DVWA returning five records after a boolean SQL injection](/assets/img/posts/sql-injection-dvwa/dvwa-boolean-injection.png)
_The tautology changed the query logic and returned every user._

### UNION-Based Version Extraction

The next payload retrieved the database version:

```sql
1' AND '1'='2' UNION SELECT null, @@version-- -
```

The deliberately false `AND '1'='2'` condition suppressed the original result. `UNION SELECT` then supplied a compatible two-column row: `null` filled the first column and `@@version` filled the second. The trailing comment ended the original statement cleanly.

DVWA displayed `5.0.51a-3ubuntu5` in the surname field. That confirmed in-band UNION extraction and showed that attacker-controlled SQL was executing without restriction.

![DVWA displaying the extracted MySQL version](/assets/img/posts/sql-injection-dvwa/dvwa-union-version.png)
_The response exposed the exact MySQL build through the application's normal output._

## 5. Automated Extraction with sqlmap

Manual confirmation came first to reduce the chance of relying on a false positive. I then used sqlmap with the authenticated DVWA session. The examples below replace the short-lived laboratory session identifier with `<LAB_SESSION>`.

### Enumerating Databases

```console
sqlmap -u "http://192.168.142.133/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<LAB_SESSION>;security=low" \
  --dbs --batch
```

sqlmap identified four viable techniques against the `id` parameter: boolean-based blind, error-based, time-based blind, and UNION query. It fingerprinted MySQL 4.1 or later, Apache 2.2.8, PHP 5.2.4, and Ubuntu 8.04 Hardy Heron.

Seven databases were accessible: `dvwa`, `information_schema`, `metasploit`, `mysql`, `owasp10`, `tikiwiki`, and `tikiwiki195`.

![sqlmap database enumeration output](/assets/img/posts/sql-injection-dvwa/sqlmap-databases.png)
_The application account could see far more than the single database it needed._

### Enumerating Tables

```console
sqlmap -u "http://192.168.142.133/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<LAB_SESSION>;security=low" \
  -D dvwa --tables --batch
```

The `dvwa` database contained `guestbook` and `users`. The second table was the credential target.

![sqlmap listing the guestbook and users tables](/assets/img/posts/sql-injection-dvwa/sqlmap-tables.png)
_Table enumeration reduced the extraction target to `dvwa.users`._

### Dumping the Users Table

```console
sqlmap -u "http://192.168.142.133/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<LAB_SESSION>;security=low" \
  -D dvwa -T users --dump --batch
```

sqlmap extracted five rows containing usernames, MD5 password hashes, avatar paths, and name fields. Its dictionary cracker recovered four seeded lab passwords: `password` for `admin`, `abc123` for `gordonb`, `charley` for user `1337`, and `letmein` for `pablo`. The CSV output was stored under sqlmap's local results directory for the target.

These were default DVWA demonstration accounts, not real users. Their recovery matters because it shows how quickly a weak application query and weak password storage can combine into full credential disclosure.

![sqlmap users table dump and hash-cracking output](/assets/img/posts/sql-injection-dvwa/sqlmap-users-dump.png)
_The complete extraction, including four cracked MD5 hashes, took roughly 54 seconds across the three commands._

## Critical Analysis

### What Worked

Nmap produced a useful service inventory without prior knowledge of the host. Its version data directly informed later choices. Dirb found both the application and an additional database-management interface with a generic word list. Manual testing proved the injection point in two stages: the boolean payload demonstrated unsafe query construction, while the UNION payload proved data extraction.

sqlmap then confirmed four injection techniques, enumerated the schema, dumped the target table, and cracked the weak hashes with little operator input. The speed of the complete chain is the important result: an attacker with intermediate knowledge could move from one unsafe parameter to exposed credentials in minutes.

### Limitations and Detection Opportunities

The controlled lab was intentionally favourable to the tools. A production environment would introduce several constraints:

- Nmap's aggressive mode creates recognisable traffic that an IDS can detect.
- Dirb only discovers names contained in its word lists, and rate limiting can slow or block it.
- sqlmap sends many malformed requests and is readily visible to a WAF, application monitoring, or well-tuned logs.
- Prepared statements make sqlmap's injection payload library ineffective because input never becomes SQL syntax.

Defenders should alert on the default `sqlmap/1.x` user agent, repeated malformed requests to one parameter, SQL keywords in URL-encoded input, and sequential requests whose values vary character by character. Correlating several of these signals in a SIEM is more reliable than treating any single match as conclusive.

### Security Impact

The result affects all three parts of the CIA triad:

- **Confidentiality:** user records, credentials, and personal data can be extracted.
- **Integrity:** write access can modify records or create administrative accounts.
- **Availability:** destructive queries can remove data or take the application offline.

Cracked passwords expand the impact further when users reuse them on other systems. One vulnerable web application can become the starting point for wider internal compromise.

## Countermeasures

### 1. Parameterised Queries and Validation

The primary fix is to keep the statement and its data separate. The vulnerable pattern was equivalent to:

```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
$result = mysql_query($query);
```

A PDO prepared statement treats the supplied value only as data:

```php
$stmt = $pdo->prepare(
    'SELECT first_name, last_name FROM users WHERE user_id = ?'
);
$stmt->execute([$id]);
$result = $stmt->fetchAll();
```

Server-side type enforcement should also reject non-integer input for an integer User ID. Validation is a supporting control; it does not replace parameterisation.

### 2. Web Application Firewall

ModSecurity with the OWASP Core Rule Set can identify common injection signatures and automated scanning. A WAF is useful defence in depth, but encoding, comments, and other obfuscation can bypass pattern matching. It should not be treated as a substitute for fixing the code.

### 3. Least-Privilege Database Accounts

The DVWA account could enumerate seven databases even though the application needed only its own. A production account should receive only the permissions required for its normal operations, limited to the application's schema. Unnecessary `FILE`, `EXECUTE`, and cross-database privileges should be removed.

### 4. Safe Error Handling

Raw MySQL errors disclose structure and help error-based injection. Users should receive a generic response, while the complete diagnostic detail is written to protected server-side logs.

### 5. Modern Password Storage

MD5 is fast, broken, and unsuitable for password storage. Passwords should be hashed with a slow, adaptive algorithm such as **Argon2id** or **bcrypt**, configured with an appropriate work factor and a unique salt for every record. This does not repair SQL injection, but it reduces the damage after a database leak.

## Final Takeaway

The most useful part of this assignment was seeing how each small weakness amplified the next. An exposed legacy stack made reconnaissance easy. A discoverable application led to an unsanitised parameter. Excessive database privileges broadened the reachable data, and MD5 turned recovered hashes into plaintext passwords almost immediately.

The tools mattered, but the core lesson was architectural: treat input as data, restrict every account to what it needs, store passwords for breach resistance, and make suspicious behaviour visible. If parameterised queries had been used at the beginning, the rest of this attack chain would have stopped at the input field.

## References

- J. Clarke, *SQL Injection Attacks and Defense*. Syngress, 2009.
- B. Damele and M. Stampar, [sqlmap: Automatic SQL Injection and Database Takeover Tool](https://sqlmap.org/), 2010.
- M. Howard and D. LeBlanc, *Writing Secure Code*, 2nd ed. Microsoft Press, 2003.
- Information Commissioner's Office, [TalkTalk Telecom Group PLC monetary penalty notice](https://ico.org.uk/media/action-weve-taken/mpns/1624661/talktalk-monetary-penalty-notice-01-october-2016.pdf), 2016.
- B. Krebs, [Payment Processor Breach May Be Largest Ever](https://www.washingtonpost.com/wp-dyn/content/article/2009/01/20/AR2009012001834.html), *The Washington Post*, 2009.
- G. Lyon, *Nmap Network Scanning*. Insecure.com LLC, 2009.
- OWASP, [ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/), 2022.
- S. Northcutt, L. Zeltser, S. Winters, K. Frederick, and R. Ritchey, *Inside Network Perimeter Security*. New Riders, 2003.
- OWASP, [A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/), 2021.
- C. Percival and S. Josefsson, [The scrypt Password-Based Key Derivation Function, RFC 7914](https://www.rfc-editor.org/rfc/rfc7914), 2016.
- R. Pinuaga, [DIRB Web Content Scanner](https://dirb.sourceforge.net/), 2009.
- Rapid7, [Metasploitable 2 Exploitability Guide](https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/), 2012.
- C. Ryan and R. Dewhurst, *Web Application Vulnerabilities: Detect, Exploit, Prevent*. Syngress, 2011.
- M. Shema, *Hacking Web Apps*. Syngress, 2012.
- D. Stuttard and M. Pinto, *The Web Application Hacker's Handbook*, 2nd ed. Wiley, 2011.
- X. Wang and H. Yu, [How to Break MD5 and Other Hash Functions](https://doi.org/10.1007/11426639_2), *EUROCRYPT 2005*, pp. 19-35.
