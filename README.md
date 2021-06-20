# Cyber-Security-Final-Project

## Homework 24 - Final Project

### Links

* [Offensive Report](./OffensiveReport.md)
* [Defensive Report](./DefensiveReport.md)
* [Network Report](./NetworkReport.md)

# Red Team: Summary of Operations

## Table of Contents
- [Exposed Services](#exposed-services)
- [Critical Vulnerabilities](#critical-vulnerabilities)
- [Exploitation](#exploitation)

### Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

```bash
$ nmap -sV -O 192.168.1.110
#  Nmap scan report for 192.168.1.110
#  Host is up (0.00072s latency).
#  Not shown: 995 closed ports
#  PORT    STATE SERVICE     VERSION
#  22/tcp  open  ssh         OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
#  80/tcp  open  http        Apache httpd 2.4.10 ((Debian))
#  111/tcp open  rpcbind     2-4 (RPC #100000)
#  139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
#  445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
#  MAC Address: 00:15:5D:00:04:10 (Microsoft)
#  Device type: general purpose
#  Running: Linux 3.X|4.X
#  OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
#  OS details: Linux 3.2 - 4.9
#  Network Distance: 1 hop
#  Service Info: Host: TARGET1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
#
#  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
#  # Nmap done at Wed Mar 24 17:59:39 2021 -- 1 IP address (1 host up) scanned in 13.33 seconds
```

This scan identifies the services below as potential points of entry:
- Target 1
  - Port 22 (SSH)
  - Port 80 (HTTP)
  - Port 111 (rpcbind)
  - Port 139 (netbios / smb)
  - Port 445 (netbios / smb)

### Critical Vulnerabilities

The following vulnerabilities were identified on each target:
- Target 1
  - `wpscan` user enumeration
    - `wpscan` was able to enumerate users and find valid usernames for the
      target system.
    - ![wp-scan-output](./images/wp-scan-output.png)
  - SSH with Password
    - Users are able to ssh into the machine with simply a password, rather than
      requiring an SSH key.
    - User `michael` had an incredibly weak password (same as his username).
  - `python` can run with sudo
    - User `steven` has the ability to run `python` with `sudo`
    - Python can execute arbitrary code on the system, so it is trivial to get
      a shell with root access using this loophole
  - Database credentials in plain text
    - Database credentials for the wordpress site were found written in plain
      text, and stored in the `/var/www/html/wp_config.php`.
    - This allowed us to access the mysql database used for the site, and
      extract password hashes and other confidential information.
  - [CVE-2017-3167](https://access.redhat.com/security/cve/CVE-2017-3167)
    - Authentication bypass is possible on the version of Apache running on the
      server
  - [CVE-2017-7494](https://www.cvedetails.com/cve/CVE-2017-7494/)
    - Version of `samba` running on the server is insecure and allows for remote
      code execution.

### Exploitation

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - `flag1.txt`: b9bbcb33e11b80be759c4e844862482d
    - **Exploit Used**
      - Weak Password / SSH with password
        - After SSHing into the host with `michael`'s credentials, we were able
          to search the `/var/www/html` directory for `flag1`.
      - Commands run:
        - `ssh michael@192.168.1.100`
        - `cd /var/www/html`
        - `grep -ER flag1`
  - `flag2.txt`: fc3fd58dcdad9ab23faca6e9a36e581c
    - **Exploit Used**
      - Weak Password / SSH with password
        - After SSHing into the host with `michael`'s credentials, `flag2` was
          found right in `/var/www`
      - Commands run:
        - `ssh michael@192.168.1.100`
        - `cd /var/www`
        - `cat flag2.txt`
  - `flag3.txt`: afc01ab56b50591e7dccf93122770cd2
    - **Exploit Used**
      - Database credentials in plain text
        - After getting the database credentials from
          `/var/www/html/wp_config.php`, we connected to the `mysql` database
          and searched for the flag.
      - Commands run:
        - `ssh michael@192.168.1.100`
        - `less /var/www/html/wp_config.php`
        - `mysql --user root --password` # Password is `R@v3nSecurity`
        - `mysql> SELECT post_title, post_content FROM wp_posts WHERE post_title LIKE "flag%";`
        - This returned the value for flag 3
  - `flag4.txt`: 715dea6c055b9fe3337544932f2941ce
    - **Exploit Used**
      - `python` can run with sudo
        - After cracking `steven`'s password using `john` and the hash found in
          the database, we determined that user `steven` could run `python` with
          `sudo` permissions.
        - This allows us to use python as sudo to execute a shell program,
          thereby granting us access to the `root` account.
        - `flag4.txt` was found in the `/root` directory, the `root` account's
          home directory.
      - Commands run:
        - `python -c 'import os; os.system("/bin/sh")'`
        - `cat flag4.txt`

# Blue Team: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further

### Network Topology

The following machines were identified on the network:
- Hypervisor / Host Machine (Not a VM)
  - **Operating System**: Microsoft Windows
  - **Purpose**: Hypervisor / Gateway
  - **IP Address**: 192.168.1.1
- ELK
  - **Operating System**: Linux
  - **Purpose**: Elasticsearch, Logstash, Kibana Server
  - **IP Address**: 192.168.1.100
- Capstone
  - **Operating System**: Linux
  - **Purpose**: Basic HTTP Server (this is a red herring)
  - **IP Address**: 192.168.1.105
- Target 1
  - **Operating System**: Linux
  - **Purpose**: HTTP Server (also wordpress site)
  - **IP Address**: 192.168.1.110
- Target 2
  - **Operating System**: Linux
  - **Purpose**: HTTP Server
  - **IP Address**: 192.168.1.115

### Description of Targets

The target of this attack was: `Target 1` (`192.168.1.110`).

Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are
possible ports of entry for attackers. As such, the following alerts have been
implemented:

* [Excessive HTTP Errors](#excessive-http-errors)
* [HTTP Request Size Monitor](#http-request-size-monitor)
* [CPU Usage Monitor](#cpu-usage-monitor)

### Monitoring the Targets

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

#### Excessive HTTP Errors
Alert 1 is implemented as follows:
  - **Metric**: `http.response.status_code` > 400
  - **Threshold**: 5 in last 5 minutes
  - **Vulnerability Mitigated**: By creating an alert, the security team can identify attacks & block the ip, change the password, & close or filter the port 22
  - **Reliability**: No, this alert does not generate a lot of false positives. This alert is highly reliable in identifying brute force attacks.

#### HTTP Request Size Monitor
Alert 2 is implemented as follows:
  - **Metric**: `http.request.bytes`
  - **Threshold**: 3500 in last 1 minute
  - **Vulnerability Mitigated**: By controlling the number of http request size through a filter it protects against DDOS attacks
  - **Reliability**: No, this alert doesn't generate a lot of false positives bc it is reliable.
#### CPU Usage Monitor
Alert 3 is implemented as follows:
  - **Metric**: `system.process.cpu.total.pct`
  - **Threshold**: 0.5 in last 5 minutes
  - **Vulnerability Mitigated**: By controlling the CPU usuage percentage at 50%, it will trigger a memory dump of stored information is generated
  - **Reliability**: Yes this alert can generate a lot of false positives bc the cpu can spike even if there is not an attack.

### Suggestions for Going Further (Optional)
- Each alert above pertains to a specific vulnerability/exploit. Recall that alerts only detect malicious behavior, but do not stop it. For each vulnerability/exploit identified by the alerts above, suggest a patch. E.g., implementing a blocklist is an effective tactic against brute-force attacks. It is not necessary to explain _how_ to implement each patch.

The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watching for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:
- Vulnerability 1- Excessive HTTP Errors
  - **Patch**: Require a stronger password policy in the user account settings. Update the account password policy in Windows group policy through /etc/security/pwquality.conf & through /etc/security/pwquality.conf in Linux
  -  **Why It Works**: By having a strong password it will be almost impossible to guess or brute force
  
- Vulnerability 2 - HTTP Request Size Monitor
  - **Patch**: Use advanced intrusion prevention and threat management systems, which combine firewalls, VPN, anti-spam, content filtering, load balancing, and other layers of DDoS defense techniques. Together they enable constant and consistent network protection to prevent a DDoS attack from happening. This includes everything from identifying possible traffic inconsistencies with the highest level of precision in blocking the attack
  - **Why It Works**: Given the complexity of DDoS attacks, there’s hardly a way to defend against them without appropriate systems to identify anomalies in traffic and provide instant response. Backed by secure infrastructure and a battle-plan, such systems can minimize the threat.
 
- Vulnerability 3 - CPU Usage Monitor
  - **Patch**: Use Host Instrusion Prevention System to identify DOS attack
  - **Why It Works**: This stops malware by monitoring the behavior of code

