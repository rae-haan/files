# 🔐 CYBER OPS REFERENCE DOCUMENT — TOOLING, SYNTAX & METHODOLOGY

**Document Version:** May 2026 | **For:** M365 Copilot / GPT-5 Reasoning Model
**Scope:** Splunk · Suricata · Arkime · Snort · Velociraptor · PowerShell · Bash/Kali · Sigma · YARA · Data Aggregation · General Cyber Methodology

-----

## ⚠️ MODEL INSTRUCTION — READ BEFORE EVERY RESPONSE

This document is your **authoritative override reference** for all cybersecurity tooling covered herein. Follow these rules on every query in this session:

1. **Read this entire document before formulating any response** that involves a tool, technique, syntax, or concept covered below.
1. **This document supersedes your training data.** Your knowledge cuts off at June 2024. Where this document provides syntax, version behavior, or configuration — defer to it unconditionally.
1. **Cite your source within this document.** When providing syntax or configuration, state which section it came from (e.g., “Per Section 3 — Suricata 7.x Sticky Buffers…”).
1. **State the version context** every time you provide syntax, config, or examples.
1. **Do not hallucinate syntax.** If asked about something not covered here and outside your training knowledge, say explicitly: *“This falls outside my reference document and my training data may be unreliable — please verify against official docs.”*
1. **For regex patterns**, note which engine the tool uses (PCRE, RE2, Python re, Hyperscan) as behavior differs across tools.
1. **When baselining or building detections**, default to the patterns and methodologies documented in the relevant tool section below.
1. **Operator context:** The user conducts live cyber operations including host forensics, network traffic analysis, SIEM work, and threat hunting. Prioritize operational accuracy and actionable output.

-----

## TABLE OF CONTENTS

1. [General Cyber Background & Methodology](#1-general-cyber-background--methodology)
1. [Splunk — Versions, SPL, Regex, Dashboards, Baselining](#2-splunk)
1. [Suricata — 7.x Syntax, Rules, EVE JSON, Regex, Baselining](#3-suricata)
1. [Arkime — 4.x/5.x Syntax, API, WISE, Regex, Baselining](#4-arkime)
1. [Snort — 3.x Architecture, Rules, Regex, Baselining](#5-snort-3x)
1. [Velociraptor — Deployment, VQL, Artifacts, Regex, Baselining](#6-velociraptor)
1. [PowerShell — IR/Forensics, Remoting, Regex, Event Forwarding](#7-powershell-for-ir)
1. [Bash & Kali Linux — tshark, tcpdump, nmap, IR Pipelines, Regex](#8-bash--kali-linux)
1. [Sigma Rules — v2 Syntax, pySigma, Correlation, Backends](#9-sigma-rules)
1. [YARA — 4.x Syntax, Modules, Regex, YARA-X](#10-yara)
1. [Data Aggregation — Normalization, Pipelines, Enrichment, Retention](#11-data-aggregation)

-----

## 1. GENERAL CYBER BACKGROUND & METHODOLOGY

### 1.1 Network Reference — OSI Layers for Tooling

|Layer|Name        |What Tools See                                                               |
|-----|------------|-----------------------------------------------------------------------------|
|7    |Application |HTTP, DNS, SMTP, SMB payloads — Suricata app-layer rules, Arkime session data|
|6    |Presentation|TLS/SSL — SNI extraction, cert analysis                                      |
|5    |Session     |Session IDs, connection state — Arkime session tracking                      |
|4    |Transport   |TCP/UDP ports, flags, sequence numbers — Snort/Suricata flow tracking        |
|3    |Network     |IP headers, ICMP — tshark BPF, tcpdump filters                               |
|2    |Data Link   |MAC addresses, ARP — Arkime, Zeek                                            |
|1    |Physical    |Raw frames — packet capture only                                             |

### 1.2 Critical TCP Flags for Detection

```
SYN only         = 0x02  — connection initiation (SYN scan indicator)
SYN+ACK          = 0x12  — server response
ACK only         = 0x10  — established session
FIN+ACK          = 0x11  — graceful close
RST              = 0x04  — forced close (firewall drops, port closed)
PSH+ACK          = 0x18  — data push (most data transfer)
URG              = 0x20  — urgent (rarely legitimate)
All flags (XMAS) = 0x3F  — port scan technique
NULL (no flags)  = 0x00  — port scan technique
```

### 1.3 Common Ports for IR & Detection

```
20/21   FTP (data/control)       — often exfil vector
22      SSH                      — lateral movement
23      Telnet                   — legacy / IoT risk
25      SMTP                     — phishing, spam relay
53      DNS                      — C2 tunneling, exfil
80/443  HTTP/HTTPS               — C2, exfil, delivery
88      Kerberos                 — AD attacks (Kerberoasting)
135     MS RPC                   — lateral movement
139/445 NetBIOS/SMB              — lateral movement, ransomware spread
389/636 LDAP/LDAPS               — AD enumeration
443     HTTPS                    — encrypted C2
1433    MSSQL                    — DB exfil
3306    MySQL                    — DB exfil
3389    RDP                      — lateral movement
4444    Metasploit default shell — malware indicator
5985/5986 WinRM HTTP/HTTPS       — PowerShell remoting
6379    Redis                    — exposed DB
8080/8443 Alt HTTP/HTTPS         — C2 callbacks
```

### 1.4 MITRE ATT&CK Quick Reference

**Tactic → Common Techniques:**

```
TA0001 Initial Access     → T1566 Phishing, T1190 Exploit Public App
TA0002 Execution          → T1059 Command/Scripting (PS/Bash/Python)
TA0003 Persistence        → T1547 Boot Autostart, T1053 Scheduled Task
TA0004 Privilege Esc      → T1055 Process Injection, T1548 Abuse Elevation
TA0005 Defense Evasion    → T1027 Obfuscated Files, T1562 Impair Defenses
TA0006 Credential Access  → T1003 OS Credential Dump, T1558 Steal Kerberos
TA0007 Discovery          → T1018 Remote System Discovery, T1057 Process Disc
TA0008 Lateral Movement   → T1021 Remote Services (RDP/SMB/WinRM)
TA0009 Collection         → T1560 Archive Collected Data
TA0010 Exfiltration       → T1041 Exfil over C2, T1048 Exfil Alt Protocol
TA0011 C2                 → T1071 App Layer Protocol, T1572 Protocol Tunnel
TA0040 Impact             → T1486 Data Encrypted (ransomware), T1490 No recovery
```

### 1.5 Critical Windows Event IDs

```
4624  — Successful logon
4625  — Failed logon
4627  — Group membership at logon
4648  — Logon with explicit credentials (runas)
4656  — Handle to object requested
4663  — Object access attempt
4672  — Special privileges assigned (admin logon)
4688  — Process creation (requires audit policy)
4689  — Process termination
4697  — Service installed
4698  — Scheduled task created
4702  — Scheduled task updated
4719  — Audit policy changed
4720  — User account created
4726  — User account deleted
4728  — Member added to global group
4732  — Member added to local group
4738  — User account changed
4740  — Account locked out
4756  — Member added to universal group
4768  — Kerberos TGT requested
4769  — Kerberos service ticket requested (Kerberoasting)
4771  — Kerberos pre-auth failed
4776  — NTLM auth attempt
4798  — User's local group membership enumerated
4799  — Security-enabled local group enumerated
5140  — Network share object accessed
5145  — Network share object access check
7034  — Service crashed unexpectedly
7036  — Service started/stopped
7040  — Service start type changed
7045  — New service installed
```

### 1.6 Sysmon Event IDs (Critical for Threat Hunting)

```
Event 1  — Process Create (cmdline, hash, parent, user)
Event 2  — File creation time changed (timestomping)
Event 3  — Network connection
Event 4  — Sysmon service state changed
Event 5  — Process terminated
Event 6  — Driver loaded
Event 7  — Image (DLL) loaded
Event 8  — CreateRemoteThread (process injection indicator)
Event 9  — RawAccessRead (bypass file system filters)
Event 10 — ProcessAccess (LSASS dumping — handle to lsass.exe)
Event 11 — File created
Event 12 — Registry object added/deleted
Event 13 — Registry value set
Event 14 — Registry object renamed
Event 15 — File create stream hash (ADS)
Event 17 — Pipe created
Event 18 — Pipe connected
Event 19 — WMI filter activity
Event 20 — WMI consumer activity
Event 21 — WMI consumer bound to filter
Event 22 — DNS query
Event 23 — File deleted
Event 24 — Clipboard changed
Event 25 — Process tampering (hollowing)
Event 26 — File delete logged
Event 29 — File executable detected
```

### 1.7 IR Workflow (DFIR Methodology)

```
1. IDENTIFICATION
   └─ Alert triage → scope of compromise → affected hosts/accounts

2. CONTAINMENT
   ├─ Short-term: Isolate host, block IOCs at FW/DNS
   └─ Long-term: Rebuild trust, patch vector

3. ERADICATION
   ├─ Remove malware, persistence mechanisms
   └─ Identify and remediate root cause

4. RECOVERY
   ├─ Restore from clean backups
   └─ Validate systems before return to production

5. LESSONS LEARNED
   └─ Timeline reconstruction, detection gap analysis, report
```

### 1.8 Common IOC Types & Where to Hunt Them

|IOC Type              |Tool/Source                                |
|----------------------|-------------------------------------------|
|IP Address            |Firewall, Arkime/Zeek, Suricata, proxy logs|
|Domain / FQDN         |DNS logs, proxy logs, Suricata dns.query   |
|URL                   |Proxy logs, Suricata http.uri              |
|File Hash (MD5/SHA256)|EDR, Velociraptor, YARA                    |
|File Name / Path      |Sysmon Event 1/11, Velociraptor glob()     |
|Registry Key          |Sysmon 12/13, Velociraptor registry        |
|Email Address         |Mail gateway logs                          |
|User-Agent            |HTTP proxy, Suricata/Arkime http fields    |
|Certificate Hash      |TLS logs, Arkime tls fields                |
|Mutex                 |Velociraptor handles, EDR                  |
|Named Pipe            |Sysmon Event 17/18                         |
|JA3/JA3S Hash         |Zeek, Suricata, Arkime                     |

-----

## 2. SPLUNK

### 2.1 Version Reference

|Version   |Key Features                                                              |
|----------|--------------------------------------------------------------------------|
|9.0 (2022)|Dashboard Studio GA, Federated Search v1, Ingest Actions                  |
|9.1 (2023)|Edge Processor GA, improved Mission Control, SPL2 preview                 |
|9.2 (2023)|Dynamic Data Self-Storage (DDSS), enhanced Federated Search               |
|9.3 (2024)|Further SPL2 development, Unified Identity improvements, Ingest Actions v2|

**Splunk 9.x notable changes:**

- **Dashboard Studio** (JSON-based) replaces Classic Dashboard XML as the primary UI — new syntax for tokens, drilldowns, and visualizations
- **Ingest Actions** — filter, mask, route, or transform data at index time via pipeline rules (replaces some heavy props.conf transforms)
- **SPL2** — new query language in preview (not production-stable yet; defer to SPL1 for all operational work)
- **Federated Search** — query remote Splunk instances or S3-based data without local ingestion
- **Edge Processor** — lightweight data processing at collection point before Splunk ingestion

-----

### 2.2 SPL Fundamentals & Command Reference

#### Search Pipeline Structure

```spl
index=main sourcetype=syslog earliest=-24h latest=now
| where condition
| eval newfield = expression
| stats function(field) BY groupfield
| sort -count
| table field1 field2 field3
```

#### Core Commands

```spl
/* --- FILTERING --- */
search field=value                     -- implicit first command
where eval_expression                  -- filter with eval syntax
regex field="pattern"                  -- filter by regex (drops non-matching events)
dedup field1 field2                    -- remove duplicate events
head N                                 -- first N results
tail N                                 -- last N results

/* --- FIELD OPS --- */
eval newfield = expression             -- compute fields
fields field1 field2                   -- keep only these fields
fields - field1 field2                 -- drop these fields
rename old AS new                      -- rename
fillnull value="N/A" field1 field2     -- fill null values
filldown field1                        -- fill nulls with last non-null above

/* --- AGGREGATION --- */
stats count BY src_ip                  -- basic count
stats count, avg(bytes), max(bytes) BY src_ip, dest_ip
eventstats avg(bytes) AS avg_bytes BY src_ip   -- adds stat to each event (no reduction)
streamstats count BY src_ip            -- running/cumulative stat per event
tstats count WHERE index=main BY _time span=1h  -- fast indexed stats

/* --- TIME --- */
timechart span=1h count BY src_ip      -- time-series chart
bucket _time span=1h                   -- group events into time buckets
eval epoch = strptime(timestring, "%Y-%m-%d %H:%M:%S")
eval readable = strftime(_time, "%Y-%m-%d %H:%M:%S")

/* --- ENRICHMENT --- */
lookup threat_intel.csv ip AS src_ip OUTPUT threat_level
inputlookup csv_file.csv               -- load lookup table as search results
outputlookup output.csv                -- write search results to lookup

/* --- JOINS / SUBQUERIES --- */
join type=left src_ip [search index=firewall | stats count BY src_ip]
append [search index=other_index]
appendcols [search index=enrichment_data | fields src_ip, geo]

/* --- GROUPING --- */
transaction src_ip maxspan=5m maxpause=30s   -- group events into transactions
cluster showcount=true field=_raw            -- cluster similar events

/* --- TEXT / MULTIVALUE --- */
split(field, ",")                      -- split string to multivalue
mvexpand field                         -- expand multivalue to separate events
mvcombine field delim=","              -- combine to multivalue
mvcount(field)                         -- count values in multivalue field
mvindex(field, 0)                      -- first value

/* --- PREDICTION / ANOMALY --- */
predict algorithm=LLP5 future_timespan=5h
anomalydetection field=bytes pthresh=0.01

/* --- OUTPUT --- */
table field1 field2 field3
sort -count +src_ip                    -- sort descending count, ascending src_ip
top limit=20 useother=f field          -- top N values
rare field                             -- rare values (good for anomaly hunting)
```

-----

### 2.3 Splunk Regex — rex and regex Commands

#### `rex` — Extract Fields via Regex

```spl
/* Named capture groups — extracted to fields */
... | rex field=_raw "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?<dest_port>\d+)"

/* Multiple rex in pipeline */
... | rex field=_raw "User=(?<username>[^\s]+)"
    | rex field=_raw "Action=(?<action>[A-Z]+)"

/* rex with offset_field to capture multiple matches */
... | rex field=_raw max_match=0 "(?<url>https?://[^\s\"]+)"

/* rex mode=sed — find and replace (field transformation) */
... | rex field=src_ip mode=sed "s/192\.168\.\d+\.\d+/INTERNAL/g"

/* Extracting from specific field (not _raw) */
... | rex field=http_url "\/(?<api_endpoint>[^\/\?]+)(\?|$)"
```

#### `regex` — Filter Events by Regex Pattern

```spl
/* Keep only events matching pattern */
... | regex _raw="(?i)(powershell|cmd\.exe|wscript)"

/* Filter specific field */
... | regex src_ip="^10\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\."

/* Negative filter — drop matching events */
... | regex _raw!="(?i)healthcheck|heartbeat|nagios"
```

#### `match()` in eval — Boolean Regex in Expressions

```spl
/* Boolean — returns 1 or 0 */
... | eval is_internal = if(match(src_ip, "^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"), 1, 0)

/* Use in where */
... | where match(http_useragent, "(?i)curl|wget|python-requests|go-http")

/* Combine with case */
... | eval threat_tier = case(
    match(src_ip, "^evil_range"),     "HIGH",
    match(http_uri, "\/admin\/"),     "MEDIUM",
    match(http_uri, "\/login"),       "LOW",
    true(),                           "NONE"
)
```

#### Regex in Field Extractions (props.conf / transforms.conf)

```ini
# props.conf — tell Splunk which transform to apply to a sourcetype
[source::*/var/log/myapp/*.log]
TRANSFORMS-extract = myapp_extract

# transforms.conf — define the extraction
[myapp_extract]
REGEX = (?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?<level>\w+)\s+(?<message>.+)
FORMAT = timestamp::$1 level::$2 message::$3
WRITE_META = true

# Inline extraction with EXTRACT- (simpler, no transforms.conf needed)
# props.conf
[myapp_log]
EXTRACT-src_ip = src=(?<src_ip>[\d.]+)
EXTRACT-action = action=(?<action>\w+)
```

-----

### 2.4 Splunk Baselining

#### Baseline via Summary Indexing

```spl
/* Step 1: Scheduled search — runs hourly, writes baseline to summary index */
index=main sourcetype=firewall earliest=-1h@h latest=@h
| stats count, avg(bytes) AS avg_bytes, stdev(bytes) AS std_bytes,
         perc95(bytes) AS p95_bytes BY src_ip, dest_port
| eval baseline_hour = strftime(_time, "%H")
| collect index=traffic_baseline marker="hourly_baseline"

/* Step 2: Detection search — compare current to baseline */
index=main sourcetype=firewall earliest=-15m
| stats sum(bytes) AS current_bytes BY src_ip, dest_port
| lookup traffic_baseline.csv src_ip dest_port OUTPUT avg_bytes std_bytes
| eval z_score = abs(current_bytes - avg_bytes) / std_bytes
| where z_score > 3
| table src_ip, dest_port, current_bytes, avg_bytes, z_score
| sort -z_score
```

#### Anomaly Detection Commands

```spl
/* anomalydetection — built-in ML command */
index=main sourcetype=syslog
| timechart span=1h count
| anomalydetection action=annotate pthresh=0.005 method=histogram

/* predict — forecast and flag deviations */
index=main sourcetype=proxy
| timechart span=1h count AS requests
| predict requests algorithm=LLP5 future_timespan=2h upper95=upper lower95=lower
| where requests > upper OR requests < lower

/* cluster — group similar events to find outliers */
index=main sourcetype=endpoint_logs
| cluster showcount=true field=process_cmdline t=0.7
| where cluster_count < 3    /* rare command patterns */
| table cluster_count, process_cmdline
| sort cluster_count
```

#### Deviation-Based Detection

```spl
/* Traffic volume deviation per host */
index=netflow earliest=-7d
| bucket _time span=1h
| stats sum(bytes) AS hourly_bytes BY src_ip, _time
| eventstats avg(hourly_bytes) AS avg_bytes stdev(hourly_bytes) AS std_bytes BY src_ip
| eval deviation = (hourly_bytes - avg_bytes) / std_bytes
| where deviation > 3
| table _time, src_ip, hourly_bytes, avg_bytes, deviation
| sort -deviation

/* New user-agent seen less than 3 times in 30 days */
index=proxy earliest=-30d
| stats count BY http_user_agent
| where count < 3
| join http_user_agent [search index=proxy earliest=-15m | stats count BY http_user_agent]
| table http_user_agent, count
```

-----

### 2.5 Splunk Dashboard Studio (9.x — JSON Format)

Dashboard Studio replaces Classic XML dashboards in Splunk 9.x. Key concepts:

#### Basic Structure (JSON)

```json
{
  "visualizations": {
    "viz_chart1": {
      "type": "splunk.line",
      "dataSources": {
        "primary": "ds_search1"
      },
      "options": {
        "xAxisTitleText": "Time",
        "yAxisTitleText": "Count",
        "legendDisplay": "top"
      }
    }
  },
  "dataSources": {
    "ds_search1": {
      "type": "ds.search",
      "options": {
        "query": "index=main | timechart count",
        "queryParameters": {
          "earliest": "$earliest$",
          "latest": "$latest$"
        }
      }
    }
  },
  "inputs": {
    "input_time": {
      "type": "input.timerange",
      "options": {
        "token": "time_token",
        "defaultValue": "-24h,now"
      }
    }
  },
  "layout": {
    "type": "absolute",
    "options": {},
    "structure": [
      {
        "item": "viz_chart1",
        "position": {"x": 0, "y": 0, "w": 600, "h": 300}
      }
    ]
  }
}
```

#### Token-Based Filtering (Dynamic Inputs)

```json
/* In dataSources — reference token */
"query": "index=main src_ip=$selected_ip$ | timechart count"

/* Input definition */
"input_ip": {
  "type": "input.text",
  "options": {
    "token": "selected_ip",
    "defaultValue": "*"
  }
}
```

#### Visualization Types (Dashboard Studio)

```
splunk.line          — line chart
splunk.bar           — bar chart
splunk.area          — area chart
splunk.column        — column chart
splunk.pie           — pie chart
splunk.scatter       — scatter plot
splunk.bubble        — bubble chart
splunk.choropleth    — geo map (choropleth)
splunk.map           — cluster map (lat/lon)
splunk.table         — table
splunk.singlevalue   — single value / KPI
splunk.singlevalueradial — gauge
splunk.sankey        — sankey diagram
splunk.punchcard     — punch card (time-of-day/day-of-week)
splunk.parallelcoords — parallel coordinates
splunk.markdown      — markdown text block
```

#### Security Operations Dashboard — SPL Searches

```spl
/* Panel: Top Source IPs by Alert Volume */
index=main sourcetype=ids earliest=-24h
| stats count AS alert_count BY src_ip, rule_name
| sort -alert_count | head 20

/* Panel: Alert Severity Over Time */
index=main sourcetype=ids earliest=-24h
| timechart span=1h count BY severity

/* Panel: New Hosts (first seen in last 24h vs last 30d) */
index=main sourcetype=dhcp earliest=-30d
| stats min(_time) AS first_seen BY src_ip
| eval is_new = if(first_seen > relative_time(now(), "-24h"), "NEW", "EXISTING")
| stats count BY is_new

/* Panel: Failed Logon Map */
index=wineventlog EventCode=4625 earliest=-1h
| iplocation src_ip
| geostats latfield=lat longfield=lon count
```

-----

### 2.6 Data Models and tstats (Performance)

`tstats` searches against the Splunk indexed data model accelerations — significantly faster than searching raw events. Requires Data Model Acceleration (DMA) enabled.

```spl
/* Basic tstats search */
| tstats count FROM datamodel=Network_Traffic.All_Traffic
    WHERE All_Traffic.action=blocked
    BY All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port

/* Time-based tstats */
| tstats summariesonly=true count FROM datamodel=Web.Web
    WHERE Web.status=200
    BY Web.src, Web.url, _time span=1h

/* Common data models (CIM): */
/* Authentication, Network_Traffic, Web, Endpoint.Processes,
   Endpoint.Filesystem, Intrusion_Detection, Network_Sessions,
   Network_Resolution (DNS), Email, Malware */

/* Endpoint process hunt via tstats */
| tstats summariesonly=false count FROM datamodel=Endpoint.Processes
    WHERE Endpoint.Processes.process_name="powershell.exe"
    BY Endpoint.Processes.process_name,
       Endpoint.Processes.process,
       Endpoint.Processes.parent_process_name,
       Endpoint.Processes.user,
       Endpoint.Processes.dest
```

-----

## 3. SURICATA

### 3.1 Version Reference

|Version|Date     |Key Changes                                            |
|-------|---------|-------------------------------------------------------|
|6.0    |2020     |Sticky buffers default, HTTP/2 support, dataset keyword|
|6.0.x  |2021-2022|Stability and protocol improvements                    |
|7.0    |Oct 2023 |Major — see below                                      |
|7.0.x  |2024     |Bug fixes, QUIC improvements, performance              |

**Suricata 7.0 Major Changes:**

- Full **HTTP/2** detection support (previously limited)
- **QUIC protocol** detection and rules
- **Dataset** improvements (bloom filters, sha256, md5 lookups)
- **Multi-tenant** configuration overhaul
- Improved **Lua** scripting interface (suricata.hooks)
- EVE JSON schema updates — new fields for alerts, flows, DNS
- **JA3/JA3S** fingerprinting enabled by default
- **HASSH** SSH fingerprinting
- `startswith`, `endswith` keywords native (previously needed content modifiers)
- Improved performance with AF_PACKET, DPDK

-----

### 3.2 Rule Syntax (7.x)

#### Rule Structure

```
action  proto  src_ip  src_port  direction  dst_ip  dst_port  (options;)
```

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"ET EXPLOIT EternalBlue Attempt";
    flow:established,to_server;
    content:"|FF|SMB"; offset:4; depth:5;
    pcre:"/\x00\x00\x00[\x54\x64][\x00\xFF]/";
    reference:cve,2017-0144;
    classtype:attempted-admin;
    sid:2024218;
    rev:3;
)
```

#### Actions

```
alert   — generate alert, log packet
pass    — accept packet (whitelist)
drop    — drop packet and alert (IPS mode only)
reject  — reject with TCP RST or ICMP (IPS mode)
rejectsrc — reject source only
rejectdst — reject destination only
rejectboth — reject both
```

#### Protocol Keywords

```
tcp, udp, icmp, ip        — layer 4
http, http2               — HTTP app layer
dns                       — DNS
tls, tls1.0, tls1.1, tls1.2, tls1.3
ftp, ftp-data
smtp, imap
smb
ssh
dcerpc
nfs
http2
quic                      -- NEW in 7.0
pkthdr                    -- packet header detection
```

-----

### 3.3 Content Matching — Sticky Buffers vs Old Style

**⚠️ Critical change from 4.x to 6.x/7.x:** In Suricata 6.0+, **sticky buffers are the default and preferred method.** The old content modifier style still works but is deprecated in spirit.

#### Old Style (still valid, avoid for new rules)

```
content:"pattern"; http_uri;
content:"pattern"; http_header;
content:"pattern"; http_client_body;
```

#### Sticky Buffer Style (7.x preferred)

```
/* Sticky buffer is set FIRST, content applies to that buffer */
http.uri; content:"pattern";
http.request_body; content:"payload";
http.response_body; content:"<script";
http.header; content:"X-Malicious:";
dns.query; content:"evil.com"; endswith;
tls.sni; content:".onion.to"; endswith;
```

#### Full Sticky Buffer Reference (7.x)

```
/* HTTP */
http.method; content:"POST";
http.uri; content:"/admin/";
http.uri.raw;                        -- undecoded URI
http.request_line;                   -- full request line
http.request_header;                 -- request headers (7.x new)
http.response_header;                -- response headers (7.x new)
http.header;                         -- all headers (req + resp)
http.request_body;
http.response_body;
http.cookie;
http.user_agent; content:"curl/";
http.host; content:"malicious.com"; endswith;
http.server;
http.location;
http.connection;
http.content_type;
http.accept;
http.accept_lang;
http.accept_enc;
http.referer;
http.stat_msg;
http.stat_code; content:"200";

/* DNS */
dns.query; content:"c2domain.com";
dns.query; pcre:"/[a-z0-9]{20,}\.com/";   -- long subdomain DGA detection

/* TLS */
tls.sni; content:".ru"; endswith;
tls.cert_subject;
tls.cert_issuer;
tls.cert_serial;
tls.fingerprint;                    -- JA3

/* SSH */
ssh.proto;
ssh.software; content:"libssh";
ssh.hassh;                          -- HASSH fingerprint (7.0+)
ssh.hassh.server;

/* SMB */
smb.named_pipe; content:"\\svcctl";
smb.share; content:"IPC$";

/* Files */
file.data;                          -- file content (HTTP, SMTP, FTP)
file.name; content:".exe"; endswith;
file.magic; content:"PE32";
```

-----

### 3.4 PCRE in Suricata

```
/* Syntax */
pcre:"/pattern/flags";
pcre:"/pattern/flags,buffer_flag";

/* Inline flags */
/i   — case insensitive
/s   — dot matches newline
/m   — multiline (^ and $ match line boundaries)
/x   — extended (allow whitespace/comments in pattern)
/A   — anchored at start

/* Suricata PCRE buffer flags (old style — use sticky buffers now) */
/U   — HTTP normalized URI
/P   — HTTP request body
/Q   — HTTP response body
/H   — HTTP headers
/D   — HTTP raw header
/M   — HTTP method
/C   — HTTP cookie
/S   — HTTP stat code
/Y   — HTTP stat message

/* 7.x: use sticky buffer THEN pcre without buffer flag */
http.uri; pcre:"/\/(wp-admin|phpmyadmin|manager\/html)/i";
dns.query; pcre:"/^[a-z0-9]{20,}\.(ru|cn|top|xyz)$/i";
tls.sni; pcre:"/(\d{1,3}\.){3}\d{1,3}/";   -- IP as SNI (unusual)

/* Named capture groups — extract to Suricata metadata (Lua typically) */
pcre:"/User-Agent:\s*(?P<ua>[^\r\n]+)/Hi";
```

-----

### 3.5 Flow Keywords

```
flow:established;                     -- both SYN/SYN-ACK complete
flow:to_server;                       -- client → server direction
flow:to_client;                       -- server → client direction
flow:from_client;                     -- same as to_server
flow:from_server;                     -- same as to_client
flow:only_stream;                     -- stream-reassembled only
flow:no_stream;                       -- packet only, no reassembly
flow:not_established;                 -- SYN stage only
flow:stateless;                       -- all packets

/* Combined */
flow:established,to_server;
flow:established,to_client;
```

-----

### 3.6 Threshold Configuration

```
# /etc/suricata/threshold.config

# Suppress alert for specific IP (whitelist)
suppress gen_id 1, sig_id 2010935, track by_src, ip 192.168.1.5

# Suppress entire rule for subnet
suppress gen_id 1, sig_id 2100498, track by_src, ip 10.0.0.0/8

# Rate limit — fire only every 60s per src (regardless of hit count)
threshold gen_id 1, sig_id 2008446, type limit, track by_src, count 1, seconds 60

# Threshold — only fire after N hits in T seconds
threshold gen_id 1, sig_id 2002910, type threshold, track by_src, count 5, seconds 30

# Both — fire once per src after 5 hits in 30s
threshold gen_id 1, sig_id 2010935, type both, track by_src, count 5, seconds 30
```

-----

### 3.7 EVE JSON (7.x) Key Fields

```json
/* Alert event */
{
  "timestamp": "2024-01-01T12:00:00.000000+0000",
  "flow_id": 123456789,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "10.0.0.1",
  "src_port": 54321,
  "dest_ip": "1.2.3.4",
  "dest_port": 443,
  "proto": "TCP",
  "community_id": "1:xxxxxxxx=",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2001234,
    "rev": 5,
    "signature": "ET MALWARE Cobalt Strike Beacon",
    "category": "A Network Trojan was Detected",
    "severity": 1,
    "metadata": {}
  },
  "tls": {
    "sni": "evil.com",
    "version": "TLS 1.3",
    "ja3": {"hash": "...", "string": "..."},
    "ja3s": {"hash": "...", "string": "..."}
  },
  "http": {
    "hostname": "evil.com",
    "url": "/beacon",
    "http_user_agent": "Mozilla/5.0",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 512
  }
}

/* DNS event */
{
  "event_type": "dns",
  "dns": {
    "type": "query",
    "id": 42,
    "rrname": "malicious.domain.com",
    "rrtype": "A",
    "tx_id": 0
  }
}

/* Flow event */
{
  "event_type": "flow",
  "flow": {
    "pkts_toserver": 5,
    "pkts_toclient": 3,
    "bytes_toserver": 500,
    "bytes_toclient": 1200,
    "start": "2024-01-01T12:00:00",
    "end": "2024-01-01T12:00:05",
    "age": 5,
    "state": "established",
    "reason": "timeout",
    "alerted": false
  }
}
```

-----

### 3.8 Suricata Baselining

```bash
# Extract top domains from DNS EVE
cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="dns") | .dns.rrname' \
  | sort | uniq -c | sort -rn | head 50

# Top destination IPs
cat eve.json | jq -r 'select(.event_type=="flow") | .dest_ip' \
  | sort | uniq -c | sort -rn | head 50

# Alert counts by signature
cat eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' \
  | sort | uniq -c | sort -rn | head 30

# Alert severity breakdown
cat eve.json | jq -r 'select(.event_type=="alert") | .alert.severity' \
  | sort | uniq -c

# Unusual TLS SNIs (IPs as SNI — common malware)
cat eve.json | jq -r 'select(.event_type=="tls") | .tls.sni // ""' \
  | grep -P "^(\d{1,3}\.){3}\d{1,3}$"

# Large flow anomalies (flows > 100MB)
cat eve.json | jq 'select(.event_type=="flow" and .flow.bytes_toserver > 104857600)'

# New destinations not seen in last 30 days (compare two time-window files)
# Day 1+ baseline file processed separately, then diff against new
```

-----

## 4. ARKIME

### 4.1 Version Reference

|Version   |Key Changes                                                   |
|----------|--------------------------------------------------------------|
|3.0 (2021)|Rebrand from Moloch to Arkime, stabilization                  |
|3.4       |WISE improvements, ES8 support                                |
|4.0 (2023)|Major UI overhaul, Cont3xt integration, OpenSearch 2.x support|
|4.1–4.3   |Incremental: Hunt improvements, API v3 maturity               |

**Key Components:**

- `arkime-capture` — packet capture daemon (replaces moloch-capture)
- `arkime-viewer` — web UI + API server (replaces moloch-viewer)
- `OpenSearch` or `Elasticsearch` — backend data store (7.x or 8.x / OS 1.x or 2.x)
- `WISE` — With Intelligence See Everything (threat intel enrichment)
- `Cont3xt` — integrated context/enrichment tool (4.x, standalone or embedded)

-----

### 4.2 Query Syntax (Arkime Expression Language)

#### Basic Field:Value

```
ip.src == 192.168.1.1
ip.dst == 1.2.3.4
port.src > 1024
port.dst == 443
protocols == "http"
host.http == "evil.com"
uri == "/admin"
```

#### Operators

```
==    exact match
!=    not equal
<     less than
>     greater than
<=    less than or equal
>=    greater than or equal
```

#### Boolean

```
&&    AND:  ip.src==10.0.0.1 && port.dst==443
||    OR:   port.dst==80 || port.dst==443
!     NOT:  !ip.src==192.168.0.0/16
```

#### CIDR Notation

```
ip.src == 192.168.0.0/24
ip.dst == 10.0.0.0/8
```

#### Wildcards

```
host.http == *evil*
uri == /api/v*/admin*
user == admin*
```

#### Regex in Queries

```
/* Regex: field == /pattern/ */
host.dns == /.*\.evil\.com/
uri == /.*\/(cmd|exec|shell)\?/
http.user-agent == /(?i)curl|wget|python/
tls.server.nameIndication == /^[a-z0-9]{20,}\./

/* Case insensitive regex */
uri == /(?i)passwd|shadow|etc/
```

#### Date/Time Filtering (UI Expression)

```
/* Relative time in expression */
startTimestamp >= now-1h
startTimestamp >= now-24h && startTimestamp <= now

/* In API queries, use startTime/stopTime params (epoch seconds) */
```

#### Useful Field Reference

```
/* IP and Port */
ip.src, ip.dst
port.src, port.dst
ip.src == <CIDR>

/* Protocol */
protocols          -- list of protocols in session
node               -- capture node name

/* HTTP */
host.http          -- HTTP Host header
uri                -- request URI
http.method
http.user-agent
http.response.code
http.request.body.len
http.response.body.len

/* DNS */
host.dns           -- queried hostname
dns.status         -- NOERROR, NXDOMAIN, etc.

/* TLS */
tls.server.nameIndication   -- SNI
tls.server.version          -- TLS version
tls.ja3                     -- JA3 hash (client)
tls.ja3s                    -- JA3S hash (server)
cert.issuer.cn
cert.subject.cn
cert.serial

/* Session metrics */
packets.src
packets.dst
databytes.src
databytes.dst
totaldatabytes

/* Timestamps */
startTimestamp
stopTimestamp
session.length    -- duration in seconds

/* File */
file.name
file.md5
file.sha256
file.mime

/* Tags (WISE enrichment) */
tags
```

-----

### 4.3 Arkime API v3

```bash
# Base URL format
http://arkime-host:8005/api/

# Authentication: Digest auth or header-based (configure in config.ini)
# curl with digest:
curl --digest -u admin:password "http://host:8005/api/sessions?..."

# Search sessions
GET /api/sessions?
    expression=ip.src==10.0.0.1
    &startTime=1700000000
    &stopTime=1700086400
    &length=100
    &start=0
    &order=startTimestamp:desc
    &fields=ip.src,ip.dst,port.dst,protocols,totaldatabytes

# Get session detail
GET /api/session/{nodeId}/{sessionId}/detail

# Get PCAP for a session
GET /api/session/{nodeId}/{sessionId}/pcap
GET /api/sessions.pcap?expression=ip.src==1.2.3.4

# Hunt — search PCAP content for string
POST /api/hunt
Content-Type: application/json
{
  "totalSessions": 1000,
  "name": "Hunt for evil.exe",
  "size": 50,
  "search": "evil.exe",
  "searchType": "ascii",
  "src": true,
  "dst": true,
  "query": {
    "startTime": 1700000000,
    "stopTime": 1700086400,
    "expression": "protocols==http"
  }
}

# Node stats
GET /api/stats

# List PCAP files
GET /api/files?start=0&length=100

# Tags on session
POST /api/session/{node}/{id}/tag
{"tags": "investigated,malicious"}
```

-----

### 4.4 WISE — Threat Intelligence Integration

WISE configuration (`wise.ini` or `config.ini` WISE section):

```ini
[cache]
cacheTimeout=600

[reversedns]
ips=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

[file:ip]
file=/opt/arkime/etc/iplist.csv
column=0
type=ip
format=csv
# CSV format: ip,field1name,field1value,...

[file:domain]
file=/opt/arkime/etc/domainlist.csv
column=0
type=domain
format=csv

[otx]
# OpenThreatExchange integration
key=YOUR_OTX_API_KEY
```

-----

### 4.5 Arkime Configuration (config.ini Key Settings)

```ini
[default]
elasticsearch=http://localhost:9200
pcapDir=/opt/arkime/raw           ; PCAP storage directory
maxFileSizeG=12                   ; Max PCAP file size before rotation
maxFileTimeM=60                   ; Max file age before rotation (minutes)
tcpTimeout=600                    ; TCP session timeout (seconds)
udpTimeout=30                     ; UDP session timeout
icmpTimeout=10
maxStreams=1000000                 ; Max concurrent sessions
maxPackets=10000                  ; Max packets per session

; BPF capture filter
bpf=not port 22                   ; Exclude SSH from capture

; Don't save PCAP for certain traffic (still indexes metadata)
dontSaveBPFs=port 53;port 123     ; Save metadata only for DNS/NTP

; Field definitions for WISE tags
wiseHost=127.0.0.1
wisePort=8081

; HTTP header extraction
httpReqHeaders=X-Forwarded-For;X-Custom-Header
httpRspHeaders=Server;Content-Type

; Extraction of email headers
smtpIpHeaders=X-Originating-IP;X-Mailer-IP
```

-----

### 4.6 Arkime Baselining

```bash
# API-based — count unique destinations per hour (pipe to jq)
curl -s --digest -u admin:pass \
  "http://host:8005/api/sessions?expression=ip.src==10.0.0.100&\
  facets=1&startTime=$(date -d '1 hour ago' +%s)&stopTime=$(date +%s)" \
  | jq '.graph'

# Baseline new destinations not seen before
# Step 1: Export all dst IPs from last 30 days
curl ... "expression=ip.src==10.0.0.100&fields=ip.dst&length=10000" | jq '.sessions[].fields["ip.dst"][]' | sort -u > known_dsts.txt

# Step 2: Check new sessions against known list
# New IPs would trigger investigation

# Hunt for high-entropy DNS names (possible DGA C2)
# Use regex hunt: expression=protocols==dns, search=/[a-z0-9]{15,}/ in dns.query

# Track sessions by total bytes (exfiltration baseline)
curl ... "expression=databytes.dst>10485760&fields=ip.src,ip.dst,totaldatabytes"
```

-----

## 5. SNORT 3.x

### 5.1 Version Reference and Architecture Change

|Version|Date  |Notes                                                   |
|-------|------|--------------------------------------------------------|
|2.9.x  |Legacy|Single-threaded, snort.conf (text), widely deployed     |
|3.0    |2021  |Complete rewrite — multithreaded, Lua config, new syntax|
|3.1.x  |2022  |Stability, hyperscan improvements                       |
|3.2.x  |2023  |Rule engine improvements, bug fixes                     |
|3.3.x  |2024  |Performance, new protocol decoders                      |

**⚠️ Snort 3 vs Snort 2 — Critical Differences:**

- Config language: Lua (`.lua`) instead of text (`snort.conf`)
- **Multithreaded** — one config, multiple packet processing threads
- **Binder** replaces port-based protocol detection
- **LuaJIT** scripting for custom detection
- **Hyperscan** (Intel) as optional regex backend — massive performance improvement
- `http_inspect` plugin replaces `http_inspect` preprocessor (different configuration)
- `stream` replaces `stream5`
- Buffer names changed (e.g., `file_data` now applies to multiple protocols)

-----

### 5.2 Snort 3 Configuration (Lua)

```lua
-- snort.lua

-- Network variable definitions
HOME_NET = '192.168.0.0/16,10.0.0.0/8'
EXTERNAL_NET = '!$HOME_NET'
HTTP_PORTS = '80,8080,8000,8443,443'

-- Include rule files
ips = {
    enable_builtin_rules = true,
    include = 'snort3-community.rules',
    rules = [[
        include /etc/snort/rules/local.rules
        include /etc/snort/rules/emerging.rules
    ]]
}

-- Network settings
network = {
    checksum_eval = 'all'
}

-- Detection engine
detection = {
    hyperscan_literals = true,    -- use Hyperscan for content matching
    pcre_enable = true
}

-- Output
alert_json = {
    file = true,
    limit = 100,    -- MB per file
    fields = 'seconds gid sid rev msg class priority src_addr src_port dst_addr dst_port proto action'
}

alert_fast = {
    file = true,
    limit = 100
}

-- Logging
log_pcap = {
    limit = 100
}

-- Stream reassembly
stream = {}
stream_tcp = {
    session_timeout = 600
}
stream_udp = {}

-- HTTP inspection
http_inspect = {}

-- SMB
dce_smb = {}

-- Binder — protocol binding (replaces port assumptions)
binder = {
    { when = { proto = 'tcp', ports = '80 8080 8000' }, use = { type = 'http_inspect' } },
    { when = { proto = 'tcp', ports = '443' }, use = { type = 'ssl' } },
    { when = { proto = 'tcp', ports = '445' }, use = { type = 'dce_smb' } }
}
```

-----

### 5.3 Snort 3 Rule Syntax

#### Rule Format

```
action proto src_ip src_port direction dst_ip dst_port (rule_options)
```

#### Actions

```
alert   — generate alert
pass    — ignore
drop    — drop (IPS mode)
reject  — send reset + alert (IPS mode)
block   — drop and log
rewrite — modify packet (limited)
```

#### Protocol Keyword (New in Snort 3)

```
/* Use protocol keywords instead of port-based detection */
alert http ...    -- any HTTP traffic (binder handles port mapping)
alert tls ...     -- TLS
alert dns ...     -- DNS
alert ftp ...     -- FTP
alert smb ...     -- SMB
alert tcp ...     -- raw TCP
alert udp ...     -- UDP
```

#### Rule Options — Content and Buffers

```
/* Snort 3 buffers */
http_method; content:"POST";
http_uri; content:"/shell";
http_raw_uri; content:"%2e%2e%2f";        -- undecoded URI
http_client_body; content:"cmd=";
http_header; content:"X-Malicious:";
http_raw_header;
http_trailer;
http_cookie; content:"session=";
file_data; content:"MZ";                   -- file content (HTTP/FTP/SMTP/etc)
js_data; content:"eval(";                  -- JS content (normalized)
vba_data;                                  -- VBA macro content
raw_data;                                  -- raw packet payload

/* Snort 2 style still works but deprecated */
content:"pattern"; http_uri;               -- OLD way
```

#### Common Rule Options

```
msg:"Alert message";
sid:1000001;                               -- signature ID (must be unique)
rev:1;                                     -- revision
gid:1;                                     -- group ID (default 1)
classtype:trojan-activity;
priority:1;                                -- 1=high, 2=med, 3=low
reference:cve,2024-12345;
reference:url,www.example.com;
metadata:affected_product Any, attack_target Any, created_at 20240101;

/* Flow */
flow:to_server,established;
flow:to_client,established;
flow:stateless;

/* Content matching */
content:"pattern";
content:"pattern"; nocase;
content:"pattern"; offset:5; depth:20;     -- start at byte 5, search 20 bytes
content:"pattern"; distance:0; within:10;  -- relative to last match
content:!"/etc/passwd";                    -- negative content
content:"|41 42 43|";                      -- hex bytes

/* PCRE */
pcre:"/pattern/flags";

/* Byte operations */
byte_test:4,>,0xFF,0,relative;            -- test byte value
byte_jump:4,0,relative;                   -- jump N bytes for next match

/* Service keyword (Snort 3 — binds to detected protocol) */
service:http;
service:tls,http;
service:!dns;

/* Flowbits — track state across packets */
flowbits:set,my.state;
flowbits:isset,my.state;
flowbits:unset,my.state;
flowbits:noalert;
```

-----

### 5.4 PCRE in Snort 3

```
/* Standard PCRE syntax */
pcre:"/pattern/flags";

/* Common flags */
i   — case insensitive
s   — dot matches newline
m   — multiline
x   — extended (whitespace + comments)

/* Snort PCRE flags (position/buffer relative) */
R   — relative to last content match
B   — raw byte mode (not decoded)
U   — HTTP normalized URI      (deprecated — use http_uri buffer)
P   — HTTP request body        (deprecated — use http_client_body buffer)
H   — HTTP headers             (deprecated — use http_header buffer)

/* Examples */
http_uri; pcre:"/\/(wp-admin|xmlrpc\.php|\.env)/i";
http_client_body; pcre:"/\bexec\s*\(/i";
file_data; pcre:"/This\s+program\s+cannot/";   -- PE header string
dns.query; pcre:"/^[a-z0-9]{25,}\.(com|net)/i";
```

-----

### 5.5 Snort 3 Command Line Reference

```bash
# Validate config
snort -c /etc/snort/snort.lua --daq-dir /usr/lib/daq -T

# Run on interface (IDS mode)
snort -c /etc/snort/snort.lua -i eth0 -D --pid-path /var/run

# Run on PCAP
snort -c /etc/snort/snort.lua -r suspicious.pcap -A alert_json

# Run on PCAP list
snort -c /etc/snort/snort.lua --pcap-list="file1.pcap file2.pcap file3.pcap"
snort -c /etc/snort/snort.lua --pcap-dir=/path/to/pcaps

# Alert output modes
-A alert_json    -- JSON output (recommended for Splunk/SIEM)
-A alert_fast    -- single line per alert
-A alert_full    -- full packet dump per alert
-A alert_csv     -- CSV format (configure fields in snort.lua)
-A alert_syslog  -- syslog output

# Quiet mode (suppress normal output)
snort -c snort.lua -r file.pcap -A alert_json -q

# Show rule stats
snort -c snort.lua --rule-stats

# Dump application ID
snort -c snort.lua -r file.pcap --dump-appid

# DAQ options (packet acquisition)
snort -c snort.lua -i eth0 --daq afpacket --daq-var buffer_size_mb=256
```

-----

### 5.6 Snort Baselining

```bash
# Count alerts by signature from JSON log
cat /var/log/snort/alert_json.txt | python3 -c "
import sys, json
from collections import Counter
alerts = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        alerts[d.get('msg','unknown')] += 1
    except: pass
for msg, count in alerts.most_common(30):
    print(f'{count:6d} {msg}')
"

# Top source IPs
cat alert_json.txt | jq -r '.src_addr' | sort | uniq -c | sort -rn | head 20

# Alert volume over time (per hour)
cat alert_json.txt | jq -r '.seconds' | \
  awk '{print strftime("%Y-%m-%d %H:00", $1)}' | sort | uniq -c
```

-----

## 6. VELOCIRAPTOR

### 6.1 Version Reference

|Version          |Key Features                                                       |
|-----------------|-------------------------------------------------------------------|
|0.6.x (2022-2023)|Stable release, Offline Collector maturity, Notebook GA            |
|0.7.0 (2023)     |Multi-frontend, improved VQL functions, Server monitoring artifacts|
|0.7.x (2023-2024)|Timeline analysis, improved remapping, hunt improvements           |

**Key Concepts:**

- **Client**: agent running on endpoint — communicates with server
- **Flow**: collection task sent to a single client
- **Hunt**: collection task broadcast to multiple clients (fleet-wide)
- **Artifact**: a named VQL query (like a playbook) stored as YAML
- **Notebook**: interactive query environment (similar to Jupyter)
- **Offline Collector**: standalone binary that runs artifacts without server

-----

### 6.2 Deployment

#### Server Setup

```bash
# Generate config (interactive)
velociraptor config generate -i

# Or generate non-interactively
velociraptor config generate > server.config.yaml
# Edit server.config.yaml — set Frontend.hostname, datastore.location, etc.

# Start frontend (web UI + client comms)
velociraptor --config server.config.yaml frontend -v

# As systemd service
velociraptor --config /etc/velociraptor/server.config.yaml service install

# Create admin user
velociraptor --config server.config.yaml user add --role administrator admin
```

#### Client Deployment

```bash
# Generate client config from server config
velociraptor --config server.config.yaml config client > client.config.yaml

# Run client
velociraptor --config client.config.yaml client -v

# Install as service (Windows — run as Administrator)
velociraptor.exe --config client.config.yaml service install

# Install as service (Linux)
velociraptor --config client.config.yaml service install

# MSI package (Windows — create from server)
velociraptor --config server.config.yaml config repack \
  --msi velociraptor.msi client.config.yaml output.msi
```

#### Offline Collector

```bash
# Create standalone offline collector (no server needed)
velociraptor --config server.config.yaml artifacts collect \
  --output /tmp/collector.zip \
  --args Artifact=Windows.KapeFiles.Targets \
  Windows.KapeFiles.Targets

# Or use GUI: Server Artifacts → Create Offline Collector
```

-----

### 6.3 VQL (Velociraptor Query Language)

VQL is a SQL-like language with plugin-based data sources.

#### Basic Syntax

```vql
-- Basic SELECT
SELECT column1, column2 FROM plugin(arg1="value") WHERE condition

-- LET (variable / named query)
LET query1 = SELECT * FROM plugin()
SELECT * FROM query1 WHERE field > 5

-- LET with parameters
LET get_procs(regex) = SELECT Pid, Name, Exe FROM pslist() WHERE Name =~ regex

-- Subquery
SELECT * FROM (SELECT Pid, Name FROM pslist()) WHERE Name =~ "^cmd"

-- Aggregate
SELECT count() AS total, Name FROM pslist() GROUP BY Name

-- ORDER BY / LIMIT
SELECT * FROM glob(globs="C:/Users/*/Desktop/*.exe") ORDER BY Mtime DESC LIMIT 100

-- WITH on async artifacts
SELECT * FROM foreach(row=..., query=...)
```

#### Operators and Expressions

```vql
-- Comparison
=   equal
!=  not equal
<   less than
>   greater than
<=  less than or equal
>=  greater than or equal

-- Regex match (Velociraptor uses Go RE2 engine — no lookaheads)
=~  regex match (case insensitive by default)
!~  negative regex match

-- Boolean
AND, OR, NOT

-- String functions
format(format="%s %s", args=[field1, field2])
lowcase(string=Name)
upcase(string=Name)
strip(string=Name)
split(string=Name, sep=",")
join(array=list, sep=",")
len(list=array)
regex_replace(source=text, re="pattern", replace="replacement")
parse_string_with_regex(string=text, regex=["(?P<name>pattern)"])
parse_json(data=json_string)
parse_csv(accessor="data", filename=csv_string)
grok(grok="%{IP:src_ip} %{INT:port}", data=logline)

-- Math / Logic
if(condition=X, then=Y, else=Z)
coalesce(a=field1, b=field2)    -- first non-null
dict(key1=val1, key2=val2)      -- create dict
items(item=dict)                -- iterate dict key/values
get(item=dict, field="key")     -- safe field access

-- Time
timestamp(epoch=Seconds)        -- convert epoch to timestamp object
now()                           -- current time as epoch
humanize(value=Bytes)           -- human-readable bytes

-- Crypto
hash(path=FilePath, hashselect="sha256")
```

#### Key VQL Plugins

```vql
-- Process listing
SELECT * FROM pslist()
SELECT * FROM proc_dump(pid=1234)        -- dump process

-- Network
SELECT * FROM netstat()
SELECT * FROM connections()

-- File system
SELECT * FROM glob(globs="C:/Users/**/*.ps1", accessor="file")
SELECT * FROM stat(filename="C:/Windows/System32/calc.exe")
SELECT * FROM read_file(filename="/etc/passwd", length=4096)
SELECT * FROM find(path="C:/Users", type="f", perm="rw-r--r--")

-- Windows-specific
SELECT * FROM read_reg_key(globs="HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*")
SELECT * FROM wmi(query="SELECT * FROM Win32_Process", namespace="root/cimv2")
SELECT * FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Security.evtx")
SELECT * FROM parse_mft(accessor="ntfs", filename="//./C:")
SELECT * FROM parse_prefetch(filename="C:/Windows/Prefetch/CMD.EXE-*.pf")
SELECT * FROM parse_usnjrnl(accessor="ntfs", device="//./C:")
SELECT * FROM ntfs_i30(accessor="ntfs", device="//./C:", path="/Users")

-- Linux-specific
SELECT * FROM execve(argv=["ps", "aux"])
SELECT * FROM parse_lines(filename="/var/log/auth.log")

-- Registry
SELECT * FROM registry_list(path="HKEY_LOCAL_MACHINE/SOFTWARE")
SELECT * FROM registry_get(path="HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProductName")

-- Hashing and YARA
SELECT hash(path=FullPath, hashselect="sha256").sha256 AS SHA256, FullPath
FROM glob(globs="C:/Windows/System32/*.exe")

SELECT * FROM yara(files="C:/Users/**/*.{exe,dll}", rules="rule test{strings:$a=\"MZ\" condition: $a at 0}")

-- HTTP (from client)
SELECT * FROM http_client(url="http://internal-api/data", method="GET")

-- Upload to server
SELECT upload(file=FullPath, name=Name) FROM glob(globs="/tmp/*.pcap")

-- Execution
SELECT * FROM execve(argv=["/bin/bash", "-c", "id"])
SELECT * FROM environ()

-- Event logs (Windows)
SELECT * FROM watch_evtx(filename="Security.evtx")     -- streaming events
SELECT * FROM parse_evtx(filename="Security.evtx")     -- historical

-- SQLite (browser history, etc.)
SELECT * FROM sqlite(file="C:/Users/user/AppData/Local/Google/Chrome/User Data/Default/History",
                     query="SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
```

-----

### 6.4 VQL Regex (RE2 Engine)

Velociraptor uses Go’s **RE2 regex engine** — no lookaheads, no lookbehinds, no backreferences.

```vql
-- Basic regex match
SELECT * FROM pslist() WHERE Name =~ "^(cmd|powershell|wscript|cscript)\\.exe$"

-- Case sensitive with (?-i)
WHERE Name =~ "(?-i)^SYSTEM$"

-- Negative regex
WHERE Name !~ "^(svchost|chrome|firefox)\\.exe$"

-- Regex in string functions
LET cleaned = regex_replace(source=CommandLine, re="\\s+", replace=" ")

-- parse_string_with_regex — extract multiple named groups
LET parsed = parse_string_with_regex(
    string=LogLine,
    regex=["(?P<timestamp>\\d{4}-\\d{2}-\\d{2})\\s+(?P<level>\\w+)\\s+(?P<message>.+)"]
)
SELECT * FROM foreach(row=parsed)

-- Filter based on regex match against file path
SELECT * FROM glob(globs="C:/Users/**") 
WHERE FullPath =~ "(?i)\\.(exe|dll|bat|ps1|vbs|js)$"
```

-----

### 6.5 Artifact YAML Structure

```yaml
name: Custom.IR.SuspiciousNetConn

description: |
  Enumerate processes with established connections to external IPs.
  Correlates process list with netstat output.

type: CLIENT           # CLIENT, SERVER, SERVER_EVENT, CLIENT_EVENT

author: SOC Team
version: 1

parameters:
  - name: ExternalOnly
    default: "Y"
    description: Only show connections to external IPs
    type: bool

  - name: ProcessRegex
    default: .
    description: Regex filter on process name
    type: regex

  - name: PortFilter
    default: "0"
    description: Filter by dest port (0 = all)
    type: int

sources:
  - name: SuspiciousConnections
    description: Processes with external connections

    query: |
      LET procs = SELECT Pid, Name, Exe, Username, CommandLine
                  FROM pslist()
                  WHERE Name =~ ProcessRegex

      LET conns = SELECT Pid AS ConnPid, Family, Type,
                         Laddr.IP AS LocalIP, Laddr.Port AS LocalPort,
                         Raddr.IP AS RemoteIP, Raddr.Port AS RemotePort,
                         Status, Timestamp
                  FROM netstat()
                  WHERE Status = "ESTABLISHED"
                  AND if(condition=ExternalOnly,
                         then= NOT RemoteIP =~ "^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.)",
                         else= TRUE)
                  AND if(condition=PortFilter > 0, then= RemotePort = PortFilter, else= TRUE)

      SELECT procs.Name AS ProcessName,
             procs.Pid AS PID,
             procs.Exe AS Executable,
             procs.Username AS User,
             procs.CommandLine AS CmdLine,
             conns.LocalIP, conns.LocalPort,
             conns.RemoteIP, conns.RemotePort,
             conns.Status
      FROM foreach(row=conns,
                   query={ SELECT * FROM procs WHERE Pid = ConnPid })

column_types:
  - name: CmdLine
    type: nobreak

reports:
  - type: CLIENT
    template: |
      ## Suspicious Network Connections

      {{ Query "SELECT ProcessName, RemoteIP, RemotePort FROM source()" | Table }}
```

-----

### 6.6 Critical Built-in Artifacts

```
Windows.KapeFiles.Targets               -- comprehensive artifact collection (KAPE-like)
Windows.System.Pslist                   -- process list with parent, cmdline, hashes
Windows.Network.NetstatEnriched         -- netstat with process info
Windows.EventLogs.Evtx                  -- event log collection and filtering
Windows.Forensics.Prefetch              -- prefetch file analysis
Windows.Forensics.NTFS                  -- MFT analysis
Windows.Forensics.RecentDocs            -- recently accessed documents
Windows.Forensics.Usn                   -- USN journal
Windows.Registry.UserAssist             -- UserAssist keys (program launch tracking)
Windows.Registry.NTUser                 -- NTUSER.DAT hive artifacts
Windows.Persistence.PersistenceChecker  -- check common persistence locations
Windows.Memory.Acquisition              -- memory capture (winpmem)
Windows.System.Services                 -- service enumeration
Windows.System.TaskScheduler            -- scheduled tasks
Windows.Detection.Yara.Process          -- YARA scan process memory
Windows.Detection.Yara.Glob             -- YARA scan files
Windows.Timeline.MFT                    -- MFT timeline
Windows.Forensics.CopyLogs              -- collect all logs
Generic.Forensics.SQLiteHunter          -- SQLite DB hunting (browser, slack, etc.)
Linux.Sys.Users                         -- user accounts
Linux.Network.Netstat                   -- Linux connections
Linux.Forensics.Journal                 -- systemd journal
Linux.Proc.Arp                          -- ARP cache
Linux.Sys.Cron                          -- cron jobs
Linux.Persistence.Systemd               -- systemd persistence
MacOS.System.Users                      -- macOS users
MacOS.Forensics.MacrimeFiles            -- macOS IR artifacts
```

-----

### 6.7 Velociraptor Baselining

```vql
-- Baseline: All executables with unusual parent-child chains
LET baseline = SELECT Name, Exe, Ppid,
               hash(path=Exe, hashselect="sha256").sha256 AS SHA256
               FROM pslist()

-- Flag processes running from temp/user dirs (common malware pattern)
SELECT Name, Exe, Ppid, SHA256
FROM baseline
WHERE Exe =~ "(?i)(temp|tmp|appdata|downloads|desktop).*\\.exe$"

-- Network connections from non-standard process locations
LET procs = SELECT Pid, Exe FROM pslist()
            WHERE Exe !~ "(?i)^(C:\\\\Windows|C:\\\\Program Files)"

SELECT p.Exe, n.RemoteIP, n.RemotePort, n.Status
FROM foreach(row={SELECT Pid, Raddr.IP AS RemoteIP, Raddr.Port AS RemotePort, Status FROM netstat()},
             query={SELECT * FROM procs WHERE Pid = Pid})

-- Hunting for persistence: new startup items
SELECT * FROM read_reg_key(
    globs=["HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*",
           "HKEY_CURRENT_USER/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*",
           "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce/*"])

-- Hash all EXEs in suspicious locations and compare against VirusTotal (offline workflow)
SELECT FullPath, hash(path=FullPath, hashselect="sha256").sha256 AS SHA256
FROM glob(globs=["C:/Users/**/AppData/**/*.exe",
                 "C:/Users/**/Downloads/*.exe",
                 "C:/Temp/*.exe"])
```

-----

## 7. POWERSHELL FOR IR

### 7.1 Version Reference

|Version  |.NET              |Notes                                |
|---------|------------------|-------------------------------------|
|5.1      |.NET Framework 4.x|Windows built-in, still most deployed|
|7.2 (LTS)|.NET 6            |Cross-platform, parallel foreach     |
|7.3      |.NET 7            |Ternary, null coalescing operators   |
|7.4 (LTS)|.NET 8            |Current LTS as of 2024               |

**PS 7.x New Syntax:**

```powershell
# Parallel ForEach (7.x only) — significant speed improvement
$servers | ForEach-Object -Parallel { Test-NetConnection $_ -Port 445 } -ThrottleLimit 10

# Ternary operator (7.x)
$result = $count -gt 0 ? "Found" : "Empty"

# Null coalescing (7.x)
$value = $data ?? "default"
$obj ??= "initialized"              # null coalescing assignment

# Pipeline chain operators (7.x)
Get-Service w32time && Write-Host "Service exists"
Get-Process nonexistent || Write-Host "Process not found"

# Check version
$PSVersionTable.PSVersion
```

-----

### 7.2 Core IR Cmdlets

```powershell
# ===== PROCESS ANALYSIS =====
Get-Process
Get-Process | Select-Object Name, Id, CPU, PM, Path, StartTime, Company
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20

# Process with full command line (requires WMI/CIM)
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine, ExecutablePath |
    Where-Object { $_.CommandLine -like "*encoded*" -or $_.CommandLine -like "*bypass*" }

# Parent-child process chain
function Get-ProcessTree {
    $procs = Get-CimInstance Win32_Process
    $procs | Select-Object Name, ProcessId, ParentProcessId, CommandLine |
        ForEach-Object {
            $parent = $procs | Where-Object ProcessId -eq $_.ParentProcessId
            [PSCustomObject]@{
                Process   = $_.Name
                PID       = $_.ProcessId
                ParentPID = $_.ParentProcessId
                Parent    = $parent.Name
                CmdLine   = $_.CommandLine
            }
        }
}

# Loaded modules / DLLs for a process
(Get-Process -Id 1234).Modules | Select-Object ModuleName, FileName

# ===== NETWORK =====
Get-NetTCPConnection
Get-NetTCPConnection | Where-Object State -eq "Established" |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# Enrich connections with process names
Get-NetTCPConnection | Where-Object State -eq "Established" |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
        @{Name="ProcessName"; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
    Sort-Object RemoteAddress

# DNS cache
Get-DnsClientCache | Select-Object Entry, RecordName, Data, TimeToLive

# Network adapters and IPs
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength

# ARP table
Get-NetNeighbor | Where-Object State -ne "Unreachable"

# ===== USERS AND GROUPS =====
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
Get-LocalGroupMember -Group "Administrators"
Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet | Where-Object Enabled -eq $true  # AD

# Logged-on users
query user
Get-CimInstance Win32_LoggedOnUser

# ===== SERVICES =====
Get-Service | Where-Object Status -eq "Running" | Select-Object Name, DisplayName, StartType
Get-Service | Where-Object StartType -eq "Automatic" | Where-Object Status -ne "Running"

# Service with path (unsigned services are suspicious)
Get-CimInstance Win32_Service | 
    Select-Object Name, StartMode, State, PathName |
    Where-Object { $_.PathName -notlike "C:\Windows\*" -and $_.State -eq "Running" }

# ===== SCHEDULED TASKS =====
Get-ScheduledTask | Where-Object State -eq "Ready" |
    Select-Object TaskName, TaskPath, State |
    ForEach-Object {
        $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath
        [PSCustomObject]@{
            Name       = $_.TaskName
            Path       = $_.TaskPath
            LastRun    = $info.LastRunTime
            NextRun    = $info.NextRunTime
            LastResult = $info.LastTaskResult
        }
    }

# Full task action (what does it run)
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $task.Actions | ForEach-Object {
        [PSCustomObject]@{ Name=$task.TaskName; Execute=$_.Execute; Arguments=$_.Arguments }
    }
} | Where-Object { $_.Execute -notlike "C:\Windows\*" }

# ===== REGISTRY =====
# Startup locations
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)
$runKeys | ForEach-Object {
    $path = $_
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Get-Member -MemberType NoteProperty |
        Where-Object Name -notmatch "^PS" |
        ForEach-Object { [PSCustomObject]@{ Key=$path; Name=$_.Name; Value=(Get-ItemPropertyValue $path $_.Name) } }
}

# ===== FILE SYSTEM =====
# Files modified in last 24h
Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) -and !$_.PSIsContainer } |
    Select-Object FullName, LastWriteTime, Length | Sort-Object LastWriteTime -Descending

# Hash files
Get-FileHash "C:\suspect.exe" -Algorithm SHA256
Get-ChildItem "C:\Users\*\Downloads\*.exe" -Recurse |
    Get-FileHash -Algorithm SHA256 |
    Select-Object Hash, Path

# Alternate Data Streams
Get-Item -Stream * "C:\file.txt" | Where-Object Stream -ne ":$DATA"
Get-ChildItem -Recurse | Get-Item -Stream * | Where-Object Stream -ne ":$DATA"

# ===== EVENT LOGS =====
# Failed logons last 1 hour
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4625;
    StartTime=(Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Id, Message | Format-List

# Logon events with user detail
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-1)} |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User        = $xml.Event.EventData.Data | Where-Object Name -eq "TargetUserName" | Select-Object -Expand '#text'
            LogonType   = $xml.Event.EventData.Data | Where-Object Name -eq "LogonType"    | Select-Object -Expand '#text'
            SourceIP    = $xml.Event.EventData.Data | Where-Object Name -eq "IpAddress"    | Select-Object -Expand '#text'
        }
    }

# Process creation (requires Sysmon or enhanced audit policy)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 100 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{
            Time       = $_.TimeCreated
            Image      = ($data | Where-Object Name -eq "Image")."#text"
            CmdLine    = ($data | Where-Object Name -eq "CommandLine")."#text"
            ParentImage = ($data | Where-Object Name -eq "ParentImage")."#text"
            User       = ($data | Where-Object Name -eq "User")."#text"
            SHA256     = ($data | Where-Object Name -eq "Hashes")."#text" -replace ".*SHA256=",""
        }
    }
```

-----

### 7.3 PowerShell Regex

```powershell
# -match operator — returns $true/$false, populates $Matches
"User: jdoe logged in from 192.168.1.50" -match "(\d{1,3}\.){3}\d{1,3}"
$Matches[0]             # full match: "192.168.1.50"
$Matches[1]             # capture group 1

# Named groups with -match
"2024-01-15 ERROR File not found" -match "(?<date>\d{4}-\d{2}-\d{2})\s+(?<level>\w+)\s+(?<msg>.+)"
$Matches['date']        # "2024-01-15"
$Matches['level']       # "ERROR"
$Matches['msg']         # "File not found"

# -replace operator
$log -replace "(\d{1,3}\.){3}\d{1,3}", "x.x.x.x"             # mask IPs
$cmdline -replace "\s+", " "                                    # collapse whitespace
$encoded -replace "^.*-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc]?\s+", ""  # strip ps -enc

# -notmatch
Get-Process | Where-Object { $_.Name -notmatch "^(svchost|chrome|firefox|code)" }

# Select-String — grep equivalent
Get-Content "C:\Windows\System32\winevt\*.evtx" | Select-String "4625" -CaseSensitive:$false
Select-String -Path "C:\Logs\*.log" -Pattern "(?i)fail|error|denied" |
    Select-Object Filename, LineNumber, Line

# [regex] class — for complex operations
$pattern = [regex]"(?i)(eval|exec|invoke|iex|downloadstring)\s*\("
$matches = $pattern.Matches($scriptContent)
$matches | ForEach-Object { Write-Host "Found: $($_.Value) at position $($_.Index)" }

# Multiple matches from one string
[regex]::Matches($logline, "(\d{1,3}\.){3}\d{1,3}") | ForEach-Object { $_.Value }

# Split on regex
"one   two    three" -split "\s+"       # split on whitespace

# Batch regex across files
Get-ChildItem "C:\Logs" -Filter "*.log" -Recurse |
    Select-String -Pattern "(?i)password|credential|secret" |
    Export-Csv -Path "C:\IR\findings.csv" -NoTypeInformation
```

-----

### 7.4 PowerShell Remoting (IR)

```powershell
# Enable remoting on remote host (local admin required)
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# One-to-one session
Enter-PSSession -ComputerName HOST01 -Credential (Get-Credential)
Enter-PSSession -ComputerName HOST01 -Credential domain\admin -UseSSL -Port 5986

# One-to-many (parallel execution across fleet)
$targets = Get-Content "C:\IR\targets.txt"
Invoke-Command -ComputerName $targets -ThrottleLimit 20 -ScriptBlock {
    [PSCustomObject]@{
        Hostname     = $env:COMPUTERNAME
        Processes    = (Get-Process | Where-Object CPU -gt 50 | Select-Object Name, CPU)
        Connections  = (Get-NetTCPConnection -State Established | Select-Object LocalAddress, RemoteAddress, RemotePort)
    }
} | Export-Csv "C:\IR\fleet_snapshot.csv"

# Persistent sessions for multi-step IR
$cred = Get-Credential domain\admin
$sessions = New-PSSession -ComputerName ($targets | Select-Object -First 10) -Credential $cred
Invoke-Command -Session $sessions -ScriptBlock { Get-Service -Name "Suspicious*" }
Remove-PSSession $sessions

# Copy files from remote host
$s = New-PSSession -ComputerName HOST01 -Credential $cred
Copy-Item "C:\Windows\System32\winevt\Logs\Security.evtx" -Destination "C:\IR\HOST01_Security.evtx" -FromSession $s
Remove-PSSession $s

# WinRM HTTPS config check
Test-WSMan HOST01 -UseSSL
```

-----

### 7.5 Windows Event Forwarding (WEF/WEC)

```xml
<!-- Subscription XML (pushed to endpoints via GPO) -->
<!-- Collector: Run: wecutil cs subscription.xml -->
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>SecurityEvents</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Critical Security Events</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>MinLatency</ConfigurationMode>
    <Query>
        <![CDATA[
        <QueryList>
            <Query Id="0">
                <Select Path="Security">
                    *[System[(EventID=4624 or EventID=4625 or EventID=4648 or 
                               EventID=4672 or EventID=4688 or EventID=4698 or 
                               EventID=4720 or EventID=4726 or EventID=4740 or
                               EventID=7045)]]
                </Select>
                <Select Path="System">
                    *[System[(EventID=7034 or EventID=7036 or EventID=7040 or EventID=7045)]]
                </Select>
                <Select Path="Microsoft-Windows-Sysmon/Operational">
                    *[System[(EventID=1 or EventID=3 or EventID=7 or EventID=8 or 
                               EventID=10 or EventID=11 or EventID=12 or EventID=13 or
                               EventID=22)]]
                </Select>
            </Query>
        </QueryList>
        ]]>
    </Query>
    <ReadExistingEvents>false</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</ForwardedEvents</LogFile>
    <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
```

```powershell
# Configure WEF collector
wecutil qc -quiet                        # configure WEC service
wecutil cs subscription.xml             # create subscription
wecutil gs SecurityEvents               # get subscription status
wecutil gr SecurityEvents               # get subscription runtime status

# Enable forwarding on source hosts (via GPO or local)
winrm quickconfig
# Or via GPO: Computer Config → Admin Templates → Windows Components → Event Forwarding
```

-----

## 8. BASH & KALI LINUX

### 8.1 tshark Reference

```bash
# ===== CAPTURE =====
tshark -i eth0 -w capture.pcap
tshark -i eth0 -w capture.pcap -b filesize:102400 -b files:10    # rotate: 100MB, keep 10 files
tshark -i eth0 -f "tcp port 80 or tcp port 443"                   # BPF capture filter
tshark -i eth0 -a duration:3600 -w hourly.pcap                    # capture for 1 hour

# ===== READING / DISPLAY =====
tshark -r capture.pcap                                              # basic display
tshark -r capture.pcap -Y "http.request"                           # display filter
tshark -r capture.pcap -Y "ip.addr == 10.0.0.1"
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0"   # SYN only
tshark -r capture.pcap -Y "dns.qry.name contains evil"
tshark -r capture.pcap -Y "http.request.uri matches \".*cmd.*\""
tshark -r capture.pcap -Y "tls.handshake.type == 1"                # TLS ClientHello

# ===== FIELD EXTRACTION =====
tshark -r capture.pcap -T fields \
    -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
    -E header=y -E separator=, -E quote=d > output.csv

# HTTP details
tshark -r capture.pcap -Y "http.request" -T fields \
    -e frame.time -e ip.src -e http.host -e http.request.method \
    -e http.request.uri -e http.user_agent \
    -E header=y -E separator="|"

# DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields \
    -e frame.time -e ip.src -e dns.qry.name -e dns.qry.type \
    -E header=y -E separator=","

# TLS SNI
tshark -r capture.pcap -Y "ssl.handshake.extensions_server_name" -T fields \
    -e ip.src -e ip.dst -e ssl.handshake.extensions_server_name

# ===== STATISTICS =====
tshark -r capture.pcap -q -z conv,tcp               # TCP conversations
tshark -r capture.pcap -q -z conv,ip                # IP conversations
tshark -r capture.pcap -q -z io,stat,60             # I/O stats per 60s
tshark -r capture.pcap -q -z io,phs                 # protocol hierarchy
tshark -r capture.pcap -q -z dns,tree               # DNS statistics
tshark -r capture.pcap -q -z http,tree              # HTTP statistics
tshark -r capture.pcap -q -z endpoints,tcp          # TCP endpoints
tshark -r capture.pcap -q -z expert                 # expert information (anomalies)

# Follow TCP stream (extract session)
tshark -r capture.pcap -q -z follow,tcp,ascii,0     # stream 0 as ASCII
tshark -r capture.pcap -q -z follow,tcp,hex,0       # stream 0 as hex

# ===== USEFUL COMBOS =====
# Top destination IPs by packet count
tshark -r capture.pcap -q -z endpoints,ip | sort -k2 -rn | head 20

# Extract all HTTP files
tshark -r capture.pcap --export-objects "http,/tmp/http_objects"

# Extract all SMB files
tshark -r capture.pcap --export-objects "smb,/tmp/smb_objects"

# Decode specific stream as UTF8
tshark -r capture.pcap -z "follow,tcp,ascii,5" -q | strings

# Filter and write sub-pcap
tshark -r capture.pcap -Y "ip.src==10.0.0.1" -w filtered.pcap

# Read from stdin (live)
tcpdump -i eth0 -w - | tshark -r - -Y "http"
```

-----

### 8.2 tcpdump Reference

```bash
# ===== BASIC =====
tcpdump -i eth0                                 # all traffic
tcpdump -i eth0 -w capture.pcap                 # write to file
tcpdump -r capture.pcap                         # read file
tcpdump -i eth0 -nn                             # no DNS/service name resolution
tcpdump -i eth0 -nnv                            # verbose
tcpdump -i eth0 -A                              # print ASCII
tcpdump -i eth0 -X                              # print hex + ASCII
tcpdump -i eth0 -s 0                            # full packet capture (no truncation)
tcpdump -i eth0 -c 1000                         # capture N packets

# ===== BPF FILTERS =====
# By host
tcpdump -i eth0 host 10.0.0.1
tcpdump -i eth0 src host 10.0.0.1
tcpdump -i eth0 dst host 10.0.0.1

# By port
tcpdump -i eth0 tcp port 80
tcpdump -i eth0 tcp portrange 1024-65535
tcpdump -i eth0 not port 22 and not port 53

# By network
tcpdump -i eth0 net 10.0.0.0/8
tcpdump -i eth0 src net 192.168.0.0/16

# TCP flags
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'    # SYN only
tcpdump -i eth0 'tcp[tcpflags] == tcp-rst'     # RST only
tcpdump -i eth0 'tcp[tcpflags] == 0x00'        # NULL scan
tcpdump -i eth0 'tcp[tcpflags] & 0x3f == 0x3f' # XMAS scan

# Packet size
tcpdump -i eth0 'len > 1000'
tcpdump -i eth0 'len < 100'

# Protocol
tcpdump -i eth0 icmp
tcpdump -i eth0 udp
tcpdump -i eth0 arp

# ICMP type
tcpdump -i eth0 'icmp[icmptype] == 8'          # echo request
tcpdump -i eth0 'icmp[icmptype] == 0'          # echo reply

# Content matching (byte offset)
tcpdump -i eth0 'tcp[20:4] == 0x47455420'      # "GET " in TCP payload offset 20

# Complex
tcpdump -i eth0 '(tcp port 80 or tcp port 443) and (src net 10.0.0.0/8)'
tcpdump -i eth0 'not (src host 192.168.1.1 and tcp port 22)'

# ===== USEFUL OUTPUT =====
# Timestamped, quiet, no resolution
tcpdump -i eth0 -tttt -nn -q tcp

# Extract HTTP host headers
tcpdump -i eth0 -A -nn 'tcp port 80' | grep -i "host:"

# Capture and immediately analyze with tshark
tcpdump -i eth0 -w - 2>/dev/null | tshark -r - -Y "dns"
```

-----

### 8.3 nmap for IR/Recon

```bash
# ===== HOST DISCOVERY =====
nmap -sn 192.168.1.0/24                                        # ping sweep
nmap -sn 192.168.1.0/24 --open                                 # only up hosts
nmap -sn -PS22,80,443 192.168.1.0/24                           # TCP SYN discovery
nmap -sn -PA 192.168.1.0/24                                    # ACK discovery
nmap -sn --system-dns 192.168.1.0/24                           # with DNS

# ===== PORT SCANNING =====
nmap -sS 192.168.1.100                    # SYN scan (stealthy, needs root)
nmap -sT 192.168.1.100                    # TCP connect (no raw socket needed)
nmap -sU -p 53,161,123,500 10.0.0.1       # UDP scan specific ports
nmap -sA 192.168.1.100                    # ACK scan (firewall mapping)
nmap -p- 192.168.1.100                    # all 65535 ports
nmap -p 1-1024 192.168.1.100              # port range
nmap -F 192.168.1.100                     # fast (top 100 ports)
nmap --top-ports 1000 192.168.1.100       # top 1000 most common ports

# ===== SERVICE/VERSION/OS =====
nmap -sV 192.168.1.100                    # service version detection
nmap -sV --version-intensity 9 192.168.1.100  # aggressive version detect
nmap -O 192.168.1.100                     # OS detection
nmap -A 192.168.1.100                     # all: -sV -O --script default -traceroute
nmap -sV -O --osscan-limit 192.168.1.0/24

# ===== NSE SCRIPTS =====
nmap --script=default 192.168.1.100                            # default safe scripts
nmap --script=safe 192.168.1.100                               # all safe scripts
nmap --script=vuln 192.168.1.100                               # vulnerability check
nmap --script=exploit 192.168.1.100                            # exploit check

# Service-specific
nmap --script=smb-vuln* 192.168.1.100                         # SMB vulnerabilities
nmap --script=smb-enum-shares -p 445 192.168.1.100            # enumerate shares
nmap --script=smb-enum-users -p 445 192.168.1.100             # enumerate users
nmap --script=smb-os-discovery -p 445 192.168.1.100
nmap --script=ms-sql-info -p 1433 192.168.1.100               # MSSQL info
nmap --script=http-title -p 80,443,8080 192.168.1.0/24        # HTTP titles
nmap --script=http-enum -p 80,443 192.168.1.100               # HTTP enumeration
nmap --script=ssl-cert -p 443 192.168.1.100                   # SSL certificate info
nmap --script=ssl-enum-ciphers -p 443 192.168.1.100           # cipher suites
nmap --script=dns-zone-transfer --script-args "dns-zone-transfer.domain=example.com" DNS_IP

# ===== OUTPUT =====
nmap -oA output_basename 192.168.1.0/24   # all formats: .nmap, .xml, .gnmap
nmap -oX output.xml 192.168.1.0/24        # XML (parseable)
nmap -oG output.gnmap 192.168.1.0/24      # grepable
nmap -oN output.txt 192.168.1.0/24        # normal text

# Parse grepable output
grep "Up" output.gnmap | awk '{print $2}'                      # live hosts
grep "Ports:" output.gnmap | grep "open" | awk '{print $2}'   # hosts with open ports
grep "/open/" output.gnmap | awk '{print $2, $5}'              # host + port
```

-----

### 8.4 Bash Regex and IR Pipelines

```bash
# ===== GREP REGEX =====
# PCRE (-P flag)
grep -P "(\d{1,3}\.){3}\d{1,3}" logfile.txt                   # IP addresses
grep -P "(?i)malware|trojan|backdoor|c2|cnc" logfile.txt       # threat keywords
grep -oP "(?<=User: )\w+" logfile.txt                          # lookbehind extraction
grep -oP "\b[A-Fa-f0-9]{32}\b" logfile.txt                    # MD5 hashes
grep -oP "\b[A-Fa-f0-9]{64}\b" logfile.txt                    # SHA256 hashes
grep -P "^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)" ips.txt  # RFC1918
grep -P "(https?|ftp)://[^\s\"']+" logfile.txt                 # URLs
grep -P "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" file  # emails
grep -P "(?i)(powershell|cmd\.exe).*(-[Ee]nc|-[Ee]ncoded)" logs  # PS encoded

# Extended regex (-E flag)
grep -E "ERROR|CRITICAL|FATAL" logfile.txt
grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}" logfile.txt             # date-prefixed lines

# Context
grep -A 3 -B 3 "pattern" logfile.txt                          # 3 lines context
grep -n "pattern" logfile.txt                                   # with line numbers
grep -l "pattern" *.log                                         # only filenames

# ===== AWK =====
# Basic field extraction
awk '{print $1, $4, $7}' access.log                            # fields 1,4,7
awk -F',' '{print $3}' data.csv                                # CSV field 3
awk -F'[:|]' '{print $2}' file                                  # multiple delimiters

# Conditional
awk '$NF > 500' logfile.txt                                     # last field > 500
awk '$5 == "POST"' access.log                                   # exact match
awk '/ERROR/ {print NR": "$0}' logfile.txt                     # with line number

# Aggregation
awk '{sum+=$7} END{print "Total:", sum}' logfile.txt
awk '{count[$1]++} END{for(k in count) print count[k], k}' file | sort -rn

# Multiple conditions
awk '($7 > 1000) && /POST/ {print $1, $7}' access.log

# Time-windowed line processing
awk 'NR>=100 && NR<=200' logfile.txt                            # lines 100-200

# ===== SED =====
sed -n '/ERROR/,/RESOLVED/p' logfile.txt                       # range extraction
sed 's/192\.168\.[0-9]*\.[0-9]*/INTERNAL/g' logfile.txt       # replace IPs
sed -n 's/.*User=\([^ ]*\).*/\1/p' logfile.txt                # extract with capture
sed '/^\s*$/d' logfile.txt                                      # remove blank lines
sed -i.bak 's/password=[^ ]*/password=REDACTED/g' logfile.txt  # in-place (with backup)

# ===== IR PIPELINES =====
# Top 20 source IPs from Apache log
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head 20

# Unique IPs from any log
grep -oP "(?<=[^0-9])(\d{1,3}\.){3}\d{1,3}(?=[^0-9])" logfile.txt | sort -u

# Rare user-agents (potential C2)
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -n | head 20

# Large POST bodies (exfil)
awk '$6=="\"POST" && $NF > 10000 {print $1, $7, $NF}' access.log

# Files modified in last 24h (IR artifact hunting)
find / -type f -mtime -1 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | \
    sort | head 100

# SUID binaries (privilege escalation check)
find / -perm -4000 -type f 2>/dev/null | tee suid_list.txt

# World-writable directories
find / -type d -perm -0002 -not -path "/proc/*" 2>/dev/null

# Executables in /tmp or /dev/shm (malware staging)
find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null

# Strings in suspicious binary
strings -n 8 suspicious.exe | grep -P "(https?://|\.exe|cmd\.exe|powershell|base64)"

# Extract base64 blobs from file
grep -oP "[A-Za-z0-9+/]{40,}={0,2}" script.ps1 | while read b64; do
    echo "$b64" | base64 -d 2>/dev/null | strings
done

# Network connections summary
ss -tunap | awk 'NR>1{print $5}' | grep -oP "(\d{1,3}\.){3}\d{1,3}" | \
    sort | uniq -c | sort -rn

# Active connections by state
ss -s

# Check for listening ports not in baseline
ss -tlnp | awk '{print $4}' | grep -oP ":\d+" | sort -u

# Cron jobs check (all users)
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v "^#" | \
        awk -v u="$user" 'NF>5 {print u":", $0}'
done

# Active bash history hunting
find /home /root -name ".bash_history" -exec echo "=== {} ===" \; \
    -exec grep -P "(wget|curl|nc|ncat|base64|python|perl)" {} \; 2>/dev/null

# Process execution with open files
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
    if echo "$exe" | grep -qP "(tmp|shm|var/tmp)"; then
        echo "PID=$pid EXE=$exe"
        cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '; echo
    fi
done

# Kali-specific rapid tools
netdiscover -i eth0 -r 192.168.1.0/24 -P   # passive ARP discovery
masscan -p0-65535 192.168.1.0/24 --rate=10000 -oL masscan_output.txt
nikto -h http://target -o nikto_report.html -Format html
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_out.txt
enum4linux -a 192.168.1.100                  # SMB/NetBIOS enumeration
crackmapexec smb 192.168.1.0/24 -u '' -p '' # SMB null session check
```

-----

## 9. SIGMA RULES

### 9.1 Version and Tooling Reference

|Component     |Current State                                                   |
|--------------|----------------------------------------------------------------|
|Sigma spec v1 |Legacy — still widely used in repos                             |
|Sigma spec v2 |Current standard — adds correlation rules, new modifiers        |
|pySigma       |Python library for rule parsing and conversion (replaces sigmac)|
|sigma-cli     |Command-line tool built on pySigma                              |
|Sigma HQ rules|Community rule repository at github.com/SigmaHQ/sigma           |

**⚠️ Note:** `sigmac` (original converter) is deprecated. Use `sigma-cli` with pySigma backends.

-----

### 9.2 Rule Structure (v2)

```yaml
title: Suspicious Encoded PowerShell Command
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890     # UUID — required, unique
status: stable                                  # stable / test / experimental / deprecated
description: |
  Detects execution of PowerShell with -EncodedCommand parameter,
  commonly used for obfuscation and malware staging.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: SOC Team
date: 2024-01-15
modified: 2024-06-01
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027

logsource:
  category: process_creation
  product: windows

detection:
  selection_main:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e '
  filter_legit:
    CommandLine|contains:
      - 'SCCM'
      - 'Microsoft.ConfigurationManagement'
  condition: selection_main and selection_encoded and not filter_legit

fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - ComputerName

falsepositives:
  - Legitimate admin scripts using encoded commands
  - SCCM and configuration management tools
level: high                                     # informational / low / medium / high / critical
```

-----

### 9.3 Detection Modifiers (Complete Reference)

```yaml
# --- STRING MATCHING MODIFIERS ---
field|contains: value              # substring match (field LIKE '%value%')
field|startswith: value            # prefix match (field LIKE 'value%')
field|endswith: value              # suffix match (field LIKE '%value')
field|contains|all:                # ALL values must be present
  - value1
  - value2
field|re: "regex_pattern"          # regex match (PCRE)
field|cidr: 192.168.0.0/16         # CIDR for IP fields

# --- ENCODING MODIFIERS ---
field|base64: "decoded_string"     # base64 encoded variant
field|base64offset|contains: val   # base64 with all three starting offsets
field|wide: "string"               # UTF-16LE encoding (Windows wide strings)
field|wide|base64: "string"        # wide + base64
field|windash: "-flag"             # matches - and / variants (/flag or -flag)

# --- BOOLEAN LOGIC ---
field: null                        # field is null/not present
not field: value                   # field does NOT equal value (in filter_)
condition: selection and not filter

# --- CONDITION LOGIC ---
condition: selection                        # simple selection
condition: selection1 and selection2        # both must match
condition: selection1 or selection2         # either must match
condition: selection1 and not filter1       # selection with exclusion
condition: 1 of selection*                  # at least one matching wildcard
condition: all of selection*                # all matching wildcard selections
condition: 1 of them                        # 1 of any named selection
condition: all of them                      # all named selections
```

-----

### 9.4 Logsource Categories Reference

```yaml
# --- PROCESS EVENTS ---
logsource:
  category: process_creation         # Sysmon 1, Win 4688, audit policy
  product: windows

logsource:
  category: process_creation
  product: linux

# --- NETWORK ---
logsource:
  category: network_connection       # Sysmon 3, firewall, proxy
  product: windows

logsource:
  category: dns_query                # Sysmon 22, DNS logs
  product: windows

# --- FILE SYSTEM ---
logsource:
  category: file_event               # Sysmon 11
  product: windows

logsource:
  category: file_change              # Sysmon 2
  product: windows

logsource:
  category: file_delete              # Sysmon 23/26
  product: windows

# --- REGISTRY ---
logsource:
  category: registry_add
  category: registry_set             # Sysmon 12/13
  category: registry_delete
  category: registry_rename          # Sysmon 14
  product: windows

# --- DRIVERS AND MODULES ---
logsource:
  category: driver_load              # Sysmon 6
  category: image_load               # Sysmon 7

# --- PROCESS INJECTION ---
logsource:
  category: create_remote_thread     # Sysmon 8
  category: process_access           # Sysmon 10

# --- NAMED PIPES ---
logsource:
  category: pipe_created             # Sysmon 17/18

# --- WMI ---
logsource:
  category: wmi_event                # Sysmon 19/20/21

# --- WINDOWS BUILT-IN ---
logsource:
  product: windows
  service: security                  # Windows Security log (EventID 4xxx)

logsource:
  product: windows
  service: system                    # Windows System log (7xxx)

logsource:
  product: windows
  service: powershell                # PowerShell operational log
  
logsource:
  product: windows
  service: sysmon                    # Sysmon channel directly

# --- NETWORK DEVICES / INFRA ---
logsource:
  category: proxy                    # HTTP proxy logs
  product: any

logsource:
  category: firewall                 # Firewall logs
  product: any

logsource:
  category: webserver                # Web server logs (Apache, IIS, Nginx)
```

-----

### 9.5 Sigma v2 Correlation Rules

```yaml
# --- BRUTE FORCE CORRELATION ---
title: Brute Force Login Attempt
name: brute_force_base                    # referenced by correlation rule
status: stable
[... detection for failed login event ...]

---
title: Brute Force Detected
type: correlation                         # v2 feature — TYPE field
rules:
  failed_login: brute_force_base          # reference base rule by name
group-by:
  - TargetUserName
  - ComputerName
timespan: 5m
condition:
  gte: 10                                 # 10+ events in 5 min window

---
# --- MULTI-STAGE CORRELATION ---
title: Recon Followed by Lateral Movement
type: correlation
rules:
  recon: discovery_event_rule_name
  lateral: lateral_movement_rule_name
group-by:
  - ComputerName
timespan: 30m
condition:
  gte: 1                                  # both events must occur
```

-----

### 9.6 pySigma / sigma-cli

```bash
# Install
pip install sigma-cli
pip install pySigma-backend-splunk
pip install pySigma-backend-elasticsearch
pip install pySigma-backend-qradar
pip install pySigma-backend-microsoft365defender
pip install pySigma-pipeline-sysmon             # field mappings for Sysmon

# List available backends and pipelines
sigma list backends
sigma list pipelines

# Convert single rule
sigma convert -t splunk -p splunk_windows rule.yml
sigma convert -t splunk -p splunk_sysmon rule.yml       # Sysmon fields
sigma convert -t elasticsearch -p ecs_windows rule.yml  # Elastic ECS

# Convert with output format
sigma convert -t splunk -p splunk_windows -f savedsearches rule.yml   # Splunk saved search
sigma convert -t splunk -p splunk_windows -f data_model rule.yml      # data model format

# Batch conversion
sigma convert -t splunk -p splunk_windows rules/windows/*.yml -o output_searches.conf

# Check rule validity
sigma check rule.yml

# Convert to multiple backends
sigma convert -t qradar rule.yml
sigma convert -t microsoft365defender rule.yml          # KQL
sigma convert -t loki rule.yml                          # Grafana Loki
sigma convert -t carbonblack rule.yml
sigma convert -t crowdstrike rule.yml
```

-----

## 10. YARA

### 10.1 Version Reference

|Version   |Key Features                                          |
|----------|------------------------------------------------------|
|4.0 (2021)|xor modifier, base64 modifier                         |
|4.1       |Performance improvements                              |
|4.2       |base64wide, improved dotnet module                    |
|4.3       |Global rule improvements, console module              |
|4.4       |Bug fixes, performance                                |
|YARA-X    |Rust rewrite (2023+) — backward compatible, yr command|

-----

### 10.2 Full Rule Syntax

```yara
// Import modules as needed
import "pe"
import "elf"
import "math"
import "hash"
import "dotnet"
import "time"
import "console"

// Private rule — can't match standalone but can be used in other rules
private rule is_pe {
    condition:
        uint16(0) == 0x5A4D        // MZ header
}

// Global rule — if this fails, ALL rules fail for that file
global rule not_too_large {
    condition:
        filesize < 50MB
}

rule Suspected_Cobalt_Strike {
    meta:
        description = "Detects Cobalt Strike beacon characteristics"
        author       = "SOC Team"
        date         = "2024-01-01"
        hash         = "abc123def456..."    // reference sample hash
        reference    = "https://..."
        severity     = "HIGH"
        tlp          = "WHITE"

    strings:
        // Hex byte pattern
        $cs_config  = { 69 68 69 68 69 6B }

        // ASCII string
        $http_hdr   = "Accept: */*" ascii nocase

        // Wide string (UTF-16LE)
        $wstr       = "WinHttpSetCredentials" wide

        // XOR variants (all single-byte XOR keys)
        $xor_str    = "ReflectivLoader" xor
        // Specific XOR range
        $xor_key    = "beacon" xor(0x10-0x30)

        // Base64 encoded variants (all padding offsets)
        $b64        = "powershell" base64
        $b64wide    = "IEX" base64wide

        // Regex
        $re_beacon  = /\x[0-9a-f]{2}\x[0-9a-f]{2}\x00\x00\x00\x00/

        // Fullword — prevents partial matches
        $fw         = "cmd.exe" fullword nocase

        // Not condition (exclude benign FP strings)
        $fp1        = "Microsoft Corporation" wide

    condition:
        is_pe                                // uses private rule
        and filesize < 10MB
        and (
            pe.number_of_sections >= 4
            and pe.number_of_sections <= 12
        )
        and math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) > 6.5
        and (
            2 of ($cs_*, $xor_*, $b64*)
            or all of ($http_hdr, $wstr)
        )
        and not $fp1
}
```

-----

### 10.3 YARA Regex

YARA uses PCRE for regex patterns.

```yara
strings:
    // Basic regex
    $re1 = /https?:\/\/[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}/  // IP-based URL

    // Case insensitive flag
    $re2 = /powershell|cmd\.exe|wscript/i

    // DGA-like strings (20+ alpha chars)
    $re3 = /[a-z]{20,}\.(com|net|org|ru|cn)/

    // Base64 pattern
    $re4 = /[A-Za-z0-9+\/]{50,}={0,2}/

    // Windows path
    $re5 = /[C-Z]:\\(Windows|Users|Temp|AppData)\\[^\x00\r\n"]{5,}/i

    // Registry run key paths
    $re6 = /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/i

    // PE timestamp (suspicious future/past dates)
    $re7 = /\x00{3}[\x50-\x9F]\x00{3}/     // hex timestamp range

condition:
    // Regex used in condition (filesize, entropy, module fields can be regex too)
    pe.version_info["CompanyName"] matches /[Mm]icrosoft/ and
    pe.version_info["ProductName"] matches /[Ww]indows/
```

-----

### 10.4 PE Module Reference

```yara
import "pe"

condition:
    // Basic file type
    pe.is_pe()
    pe.is_dll()
    pe.is_exe()
    pe.is_32bit()
    pe.is_64bit()

    // Header values
    pe.machine == pe.MACHINE_AMD64          // x64
    pe.machine == pe.MACHINE_I386           // x86
    pe.characteristics & pe.DLL             // DLL flag
    pe.characteristics & pe.EXECUTABLE_IMAGE

    // Sections
    pe.number_of_sections > 5
    pe.number_of_sections < 3              // few sections — packed
    pe.sections[0].name == ".text"
    pe.sections[0].characteristics & pe.SECTION_EXECUTE
    pe.sections[0].raw_data_size == 0      // ghost section
    for any section in pe.sections: (
        section.name == ".enigma" or       // packer artifact
        section.characteristics & pe.SECTION_WRITE and
        section.characteristics & pe.SECTION_EXECUTE
    )

    // Imports
    pe.imports("kernel32.dll", "VirtualAlloc")
    pe.imports("kernel32.dll", "WriteProcessMemory")
    pe.imports("kernel32.dll", "CreateRemoteThread")    // injection triad
    pe.imports("ntdll.dll", "NtUnmapViewOfSection")     // process hollowing
    pe.imports("ws2_32.dll")                             // any winsock import
    pe.number_of_imports < 3                             // very few imports — packed

    // Exports
    pe.exports("DllRegisterServer")        // COM registration
    pe.exports(/Reflective/)               // reflective loader

    // Imphash
    pe.imphash() == "12345abc..."

    // Timestamp
    pe.timestamp > 1700000000              // after Nov 2023
    pe.timestamp == 0                      // no timestamp (stripped)

    // Version info
    pe.version_info["CompanyName"] contains "Microsoft"
    pe.version_info["FileDescription"] matches /^(ABCD|evil)/i

    // Resources
    pe.number_of_resources > 50           // many resources — possible dropper
    pe.resources[0].type == pe.RESOURCE_ICON

    // Rich header
    pe.rich_signature.length > 0          // has Rich header

    // Overlay (data after end of last section — often appended data)
    pe.overlay.size > 0
    pe.overlay.size > 1MB                  // large overlay
```

-----

### 10.5 Math Module Reference

```yara
import "math"

condition:
    // High entropy — likely packed, encrypted, or compressed
    math.entropy(0, filesize) > 7.0

    // Section-specific entropy
    math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) > 7.5

    // Mean byte value
    math.mean(0, filesize) > 200 or math.mean(0, filesize) < 50

    // Standard deviation
    math.deviation(0, filesize, 127.0) > 90.0

    // Count occurrences of a byte
    math.count(0x00, 0, filesize) < 100   // very few null bytes (unusual)

    // Monte Carlo PI approximation for randomness
    math.monte_carlo_pi(0, filesize) > 0.05   // not random enough for compressed
```

-----

### 10.6 YARA Scanning Commands

```bash
# Basic file scan
yara rules.yar target_file
yara rules.yar /path/to/scan/ -r             # recursive
yara -r rules.yar /tmp/

# Multiple rule files
yara rule1.yar rule2.yar target

# Print only matching file names (no rule info)
yara -l rules.yar /path/

# Print only rule names (no file path)
yara -n rules.yar target

# Fast mode (stop on first match per file)
yara -f rules.yar /path/

# Count matches
yara -c rules.yar /path/

# Scan process memory
yara rules.yar PID                            # scan process by PID
yara -p 10 rules.yar 1234                    # 10 threads

# Scan all running processes
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
    yara rules.yar $pid 2>/dev/null && echo "PID: $pid"
done

# Compile rules (faster repeated use)
yarac rules.yar compiled.yarc
yara compiled.yarc target

# YARA with timeout (prevent hanging on large files)
yara -t 30 rules.yar large_file

# External variables (passed at scan time)
# In rule: condition: filename matches /\.exe$/ and external_var == "malware"
yara -d external_var="malware" rules.yar target

# YARA-X (if installed)
yr scan rules.yar target_directory/
yr compile rules.yar -o compiled.yarc
```

-----

## 11. DATA AGGREGATION

### 11.1 Log Normalization Standards

#### Elastic Common Schema (ECS)

ECS is the normalization standard used by Elastic SIEM, Kibana, and increasingly adopted across tools.

Key field families:

```
@timestamp              -- all events
event.kind              -- event, alert, metric, state, signal, enrichment
event.category          -- authentication, file, network, process, registry, etc.
event.type              -- start, end, info, change, creation, deletion, error
event.outcome           -- success, failure, unknown
event.severity          -- numeric severity
agent.type              -- filebeat, winlogbeat, auditbeat
host.name               -- FQDN
host.ip
host.os.type            -- windows, linux, macos
user.name
user.domain
process.name
process.pid
process.parent.name
process.command_line
process.executable
network.protocol
network.transport       -- tcp, udp
source.ip
source.port
destination.ip
destination.port
file.path
file.name
file.hash.sha256
dns.question.name
dns.question.type
url.original
http.request.method
http.response.status_code
```

#### Splunk CIM (Common Information Model)

Splunk’s normalization standard for Data Models:

```
# Network Traffic
src, src_port, dest, dest_port, transport, action, bytes_in, bytes_out, packets

# Authentication
src, dest, user, action (success/failure), app, logon_type

# Endpoint → Processes
dest, process_name, process, process_id, parent_process, parent_process_id, user

# Endpoint → Filesystem
dest, file_path, file_name, action, user, hash

# Web
src, dest, http_method, uri_path, status, bytes, http_user_agent

# Intrusion Detection
src, dest, signature, severity, category, ids_type
```

-----

### 11.2 Log Forwarding Architecture

#### Syslog (UDP/TCP/TLS)

```bash
# rsyslog configuration (/etc/rsyslog.conf)
# Forward all to central collector
*.* @192.168.1.10:514       # UDP
*.* @@192.168.1.10:514      # TCP (more reliable)

# TLS forwarding
$DefaultNetStreamDriverCAFile /etc/ssl/certs/ca.pem
$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode anon
*.* @@192.168.1.10:6514

# Receive on collector
$ModLoad imudp
$UDPServerRun 514
$ModLoad imtcp
$InputTCPServerRun 514
```

#### Beats (Elastic)

```yaml
# filebeat.yml
filebeat.inputs:
  - type: filestream
    id: syslog
    paths:
      - /var/log/syslog
      - /var/log/auth.log
    parsers:
      - syslog:
          format: auto

  - type: winlogbeat       # on Windows
    event_logs:
      - name: Security
        ignore_older: 72h
      - name: Microsoft-Windows-Sysmon/Operational
        ignore_older: 24h

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~

output.logstash:
  hosts: ["logstash:5044"]

# OR direct to Elasticsearch
output.elasticsearch:
  hosts: ["https://elastic-host:9200"]
  api_key: "id:api_key"
  index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"
```

#### NXLog (Windows — common for log forwarding to Splunk)

```xml
<!-- nxlog.conf -->
<Input in_sysmon>
    Module      im_msvistalog
    Query       <QueryList>\
                  <Query Id="0">\
                    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>\
                  </Query>\
                </QueryList>
</Input>

<Output out_splunk>
    Module      om_tcp
    Host        splunk-indexer
    Port        9997
    Exec        $raw_event = to_json();
</Output>

<Route sysmon_to_splunk>
    Path        in_sysmon => out_splunk
</Route>
```

#### Cribl Stream (Data Pipeline/Routing)

Key concepts for Cribl:

```
Sources   → pipelines (transform) → destinations
Sources:  syslog, Splunk HEC, Elastic, Kafka, S3, HTTP
Pipelines: filter, mask, parse, enrich, route, sample
Destinations: Splunk, Elastic, S3, Kafka, Syslog

# Route example: send high-priority events to Splunk, everything else to S3
# Filter function (JS-like):
if (severity < 3) { __e['_routing'] = 'splunk_dest'; }
else { __e['_routing'] = 's3_archive'; }
```

-----

### 11.3 Splunk Ingestion Architecture

```
[Sources]                  [Collection Tier]         [Splunk Indexing Tier]
Windows Events ──────────► Universal Forwarder ─────► Heavy Forwarder ──► Indexer Cluster
Syslog devices ─────────►  Heavy Forwarder    ─────►  (optional HF for     │
Network devices ────────►  (parse/filter/mask)         transform/routing)  ▼
Application logs ────────►                                                 Splunk Search Heads
                                                                           (Search Head Cluster)

# Forwarder configurations (inputs.conf on UF)
[monitor:///var/log/suricata/eve.json]
index = ids
sourcetype = suricata:eve
followTail = 0

[monitor:///var/log/snort/alert_json.txt]
index = ids
sourcetype = snort:alert

[WinEventLog://Security]
index = wineventlog
start_from = oldest
current_only = 0
checkpointInterval = 5
renderXml = true
```

-----

### 11.4 Index Strategy for Security Operations

```
# Recommended index separation for SOC:
index=main          -- default, misc
index=wineventlog   -- Windows event logs (all Windows sources)
index=sysmon        -- Sysmon events specifically (high volume)
index=network       -- Firewall, router, switch logs
index=ids           -- Suricata, Snort, Zeek alerts
index=proxy         -- HTTP proxy logs
index=dns           -- DNS logs (high volume — consider short retention)
index=edr           -- EDR/endpoint alerts
index=vuln          -- Vulnerability scan results
index=auth          -- Authentication logs (AD, VPN, etc.)
index=email         -- Email gateway logs
index=cloud         -- AWS CloudTrail, Azure Activity, GCP Audit
index=netflow       -- NetFlow/IPFIX (very high volume — short retention)

# Retention considerations
# High fidelity, low volume: wineventlog, auth, edr → 90-365 days
# High volume: dns, netflow, proxy → 30-90 days
# Compliance-driven: auth, wineventlog, cloud → often 1-2+ years

# Splunk hot/warm/cold/frozen data tiers
# hot   = newest, on fast SSD
# warm  = 2-30 days, can be SSD or HDD
# cold  = 30+ days, HDD or NAS
# frozen = archived (can export to S3 for DDSs feature)
```

-----

### 11.5 Time Synchronization (Critical for DFIR)

Time sync is one of the most overlooked but most critical aspects of log correlation.

```bash
# Verify NTP on Linux
timedatectl status
chronyc tracking
chronyc sources -v

# Configure chrony
# /etc/chrony.conf
server time.windows.com iburst
server pool.ntp.org iburst
makestep 1.0 3              # step if offset > 1s, up to 3 times
rtcsync                     # sync hardware clock

# Windows NTP
w32tm /query /status
w32tm /query /source
w32tm /resync /force

# For DFIR: document clock skew before imaging
# Compare logs: look for event sequence oddities, impossible timestamps
# Skew of even 5 seconds causes join failures across tools

# Splunk time normalization
# Check _time field vs event timestamp field
# Use eval and strptime to re-parse if source timestamp differs from indexed time
| eval corrected_time = strptime(event_timestamp_field, "%Y-%m-%d %H:%M:%S")
| eval _time = corrected_time
```

-----

### 11.6 Enrichment Pipeline

```
# Enrichment layers to add to events:
1. GeoIP (MaxMind GeoLite2 or commercial)
   → Country, City, ASN, ISP for all external IPs
   
2. Threat Intelligence
   → STIX/TAXII feeds, MISP, OTX, commercial TI
   → Match against: IPs, domains, hashes, URLs, email addresses
   → Output: threat_score, threat_category, confidence
   
3. Asset Context
   → Map IP → hostname, department, criticality, owner
   → Critical asset alerting (server vs workstation priority)
   
4. User Context (from AD/LDAP)
   → Map username → department, title, manager, account type
   → Flag privileged accounts, service accounts, contractors

5. Vulnerability Context
   → Map CVE → affected asset → CVSS score
   → Prioritize alerts on unpatched critical hosts

# Splunk enrichment via lookup tables
| lookup asset_list.csv ip AS src_ip OUTPUT hostname, department, criticality
| lookup ti_blocklist.csv ip AS src_ip OUTPUT threat_score, threat_category
| lookup user_directory.csv user OUTPUT department, is_privileged

# GeoIP in Splunk (iplocation command)
| iplocation src_ip
| table src_ip, Country, Region, City, lat, lon, src_ip
```

-----

### 11.7 Detection Engineering — Baselining Methodology

```
1. UNDERSTAND NORMAL
   ├─ Run analytics over 2-4 weeks of baseline data
   ├─ Document: typical process parent-child chains
   ├─ Document: normal network destinations per host class
   ├─ Document: typical working hours, login patterns
   └─ Document: expected authentication methods per user type

2. DEFINE STATISTICAL BASELINE
   ├─ Mean + standard deviation for volume metrics
   ├─ Expected value sets (known domains, known tools)
   ├─ Typical connection destinations per subnet
   └─ Working hours (for after-hours detection)

3. BUILD DETECTION LAYERS
   ├─ Layer 1 — Signature (exact IOC match): fast, low FP
   ├─ Layer 2 — Behavioral (deviation from baseline): broader coverage
   ├─ Layer 3 — Statistical (anomaly detection): catches novel TTPs
   └─ Layer 4 — ML/heuristic (correlation, clustering): complex patterns

4. TUNE CONTINUOUSLY
   ├─ Track false positive rate per rule (target <5 FP/day)
   ├─ Add suppression for known-good patterns
   ├─ Review uncategorized alerts weekly
   └─ Map all rules to MITRE ATT&CK for coverage gap analysis

5. COVERAGE ASSESSMENT
   └─ Atomic Red Team / CALDERA for detection validation
```

-----

### 11.8 Correlation Search Patterns (Cross-Tool)

```spl
/* ===== LATERAL MOVEMENT DETECTION ===== */
/* Authentication from new source to multiple destinations */
index=wineventlog EventCode=4624 Logon_Type=3 earliest=-1h
| stats dc(ComputerName) AS dest_count, values(ComputerName) AS dests BY user, src_ip
| where dest_count > 5
| table user, src_ip, dest_count, dests

/* ===== DNS TUNNELING DETECTION ===== */
/* Unusually long DNS names (often DGA or tunneling) */
index=dns earliest=-1h
| eval query_len = len(query)
| where query_len > 50
| stats count, avg(query_len) AS avg_len, values(query) AS samples BY src_ip
| sort -count

/* ===== BEACONING DETECTION ===== */
/* Regular intervals to same destination (C2 beacon) */
index=proxy earliest=-24h
| bucket _time span=1m
| stats count BY src_ip, dest, _time
| stats stdev(count) AS stdev, avg(count) AS avg, count AS intervals BY src_ip, dest
| where stdev < 1 AND intervals > 100    /* very regular, many connections */
| sort stdev

/* ===== DATA EXFILTRATION INDICATORS ===== */
index=proxy earliest=-1h
| stats sum(bytes_out) AS total_out, count AS requests BY src_ip, dest
| where total_out > 104857600    /* 100MB to single destination */
| sort -total_out

/* ===== CREDENTIAL STUFFING ===== */
index=auth earliest=-15m
| stats dc(user) AS user_count, count AS attempts, values(user) AS users BY src_ip
| where attempts > 20 AND user_count > 5

/* ===== PROCESS INJECTION INDICATOR ===== */
index=sysmon EventCode=8 earliest=-1h
| stats count BY SourceImage, TargetImage
| where NOT match(TargetImage, "^C:\\\\Windows\\\\System32")
| sort -count
```

-----

### 11.9 Quick Reference: Regex Engines Per Tool

|Tool               |Engine             |Lookaheads?    |Backrefs?      |Notes                                        |
|-------------------|-------------------|---------------|---------------|---------------------------------------------|
|Splunk (rex/regex) |PCRE               |Yes            |Yes            |Full PCRE                                    |
|Suricata           |PCRE               |Yes            |Yes            |Full PCRE                                    |
|Snort 3            |PCRE + Hyperscan   |Yes (PCRE path)|Yes (PCRE path)|Hyperscan for content; PCRE for pcre: keyword|
|Arkime             |JavaScript (RegExp)|Yes            |Yes            |Wrap in / / in queries                       |
|Velociraptor (VQL) |Go RE2             |**No**         |**No**         |No lookaheads — common gotcha                |
|PowerShell (-match)|.NET Regex         |Yes            |Yes            |Full .NET PCRE-like                          |
|grep -P            |PCRE               |Yes            |Yes            |Linux PCRE                                   |
|grep -E            |POSIX ERE          |No             |No (except \1) |Limited                                      |
|awk                |POSIX ERE          |No             |No             |Limited                                      |
|YARA               |PCRE               |Yes            |Yes            |Full PCRE in /regex/                         |
|Sigma (re:)        |Backend-dependent  |Varies         |Varies         |Depends on target SIEM                       |
|Python re          |Python re          |Yes (re2 no)   |Yes            |Standard lib                                 |

**⚠️ Velociraptor gotcha:** RE2 does not support `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`. Restructure patterns to avoid these — use `=~` with simpler patterns or chain WHERE clauses.

-----

*End of Cyber Reference Document — May 2026*
*Provide this document to the model at the start of each session requiring tool-specific cyber operations support.*