# Building a WAF & SIEM Pipeline: Nginx, ModSecurity, and Wazuh

![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-00A9E0?style=for-the-badge&logo=wazuh&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-000000?style=for-the-badge&logo=owasp&logoColor=white)

## Project Overview
This project simulates a real-world **Security Operations Center (SOC)** workflow. I deployed a **Web Application Firewall (WAF)** using Nginx and ModSecurity to protect a vulnerable legacy application (DVWA).

The critical component of this project is the **Log Pipeline**. Instead of reviewing logs manually on the server, I engineered a pipeline to forward WAF detection logs to a **Wazuh SIEM** for real-time threat analysis, alerting, and forensic auditing.

### Architecture
* **Victim**: DVWA (Damn Vulnerable Web App) running in a Docker container.
* **Defense**: Nginx Reverse Proxy + ModSecurity (OWASP Core Rule Set).
* **Monitoring**: Wazuh SIEM (Manager & Agent).
* **Flow**: `Attacker -> WAF (Port 8080) -> [Logs to SIEM] -> Victim App (Port 80)`
![architecture](images/screenshot1.png)
---

## Infrastructure Setup

The entire lab is containerized using Docker Compose for portability and isolation.

**1. Container Status**
I orchestrated the environment to ensure the WAF sits directly in front of the application network.
![Infrastructure Status](images/screenshot2.png)

**2. Configuring the Victim**
To validate the WAF's effectiveness, I disabled the application's internal defenses (Security Level: Low), making the WAF the only line of defense.
![DVWA Configuration](images/screenshot3.png)

---

## Attack & Defense Simulation

I validated the WAF configuration by launching two common OWASP Top 10 attacks.

### Test 1: SQL Injection (SQLi)
**Attack Vector:** I simulated an external attacker attempting to bypass authentication and dump the database using a boolean-based payload:
`' OR 1=1 --`
![SQLi Block](images/screenshot4.png)
**Result: Intercepted**
The WAF inspected the HTTP Request Body (Layer 7), identified the SQL pattern matching **OWASP Rule 942100**, and severed the connection immediately.

![SQLi Block](images/screenshot5.png)

### Test 2: Cross-Site Scripting (XSS)
**Attack Vector:** I attempted to inject a malicious script into the application to test for Reflected XSS:
`<script>alert('You are Hacked')</script>`
![XSS Block](images/screenshot6.png)
**Result: Intercepted**
The WAF detected the `<script>` tags and JavaScript keywords in the input field, matching **OWASP Rule 941100** (XSS Attacks), and blocked the request.

![XSS Block](images/screenshot7.png)

---

## SIEM Integration & Analysis

A WAF block is useless if the SOC team doesn't know about it. I configured the Wazuh Agent to monitor the ModSecurity audit logs (`modsec.log`) in real-time.

**1. Threat Detection (Dashboard)**
Wazuh successfully ingested the log, decoded the Nginx error format, and triggered a **Level 7 Security Alert**.

![Wazuh Dashboard](images/screenshot8.png)

**2. Forensic Deep Dive**
Drilling down into the alert JSON reveals the exact payload used by the attacker, allowing for proper incident classification.

**SQLi Log Evidence:**
![SQLi JSON Analysis](images/screenshot9.png)

**XSS Log Evidence:**
![XSS JSON Analysis](images/screenshot10.png)

---

## Configuration Snippets

### Docker Compose (The Stack)
The WAF is configured as a Reverse Proxy using the `OWASP/modsecurity-crs` image.

```yaml
services:
  waf:
    image: owasp/modsecurity-crs:nginx
    ports:
      - "8080:8080"
    environment:
      - PROXY=1
      - BACKEND=http://dvwa:80
      - PARANOIA=1
    volumes:
      - ./logs:/var/log/modsec/
    depends_on:
      - dvwa
```
### Wazuh Agent Config (ossec.conf)
I added a custom log collector to read the WAF's output stream.

```XML

<localfile>
  <location>/tmp/modsec.log</location>
  <log_format>syslog</log_format>
</localfile>
```
## Conclusion
This project successfully demonstrated the end-to-end implementation of a **Threat Detection Pipeline**. By integrating an **Nginx-based WAF** with **Wazuh SIEM**, I moved beyond simple "tool installation" to engineering a cohesive security architecture. 

The lab proved that while signature-based detection (OWASP CRS) is effective against common web attacks like SQLi and XSS, the real value lies in the **centralized visibility** provided by the SIEM. The ability to correlate a WAF block with specific threat intelligence in real-time is what transforms raw logs into actionable security insights.

## Future Scope
To evolve this project from a "Lab Environment" to a "Production-Ready Architecture," the following enhancements are planned:

* ** Active Response:** Configure Wazuh to automatically trigger a firewall ban (via `iptables`) on the host server for any IP address that triggers more than 5 WAF alerts in 1 minute.
* ** Automated Alerting:** Set up a Wazuh integration with **Slack** to send real-time notifications for High-Severity (Level 10+) WAF blocks.
