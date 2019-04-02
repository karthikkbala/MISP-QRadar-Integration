# QRadar MISP Integration
Integrate QRadar with IOC (Attributes) from MISP - Open Source Threat Intelligence Platform

### IBM QRadar:
 
![alt text](https://www.threatconnect.com/wp-content/uploads/QRadar-logo-Website.png "IBM QRadar")

IBM QRadar Security Information and Event Management (SIEM) centrally collects and analyzes log and network flow data throughout even the most highly distributed environments to provide actionable insights into threats.

Using advanced analytics, the solution automatically sorts through millions to billions of events per day to detect anomalous and malicious activities, identify and group related events, and generate prioritized alerts to only the most critical threats.

### MISP:

![alt text](https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/logos/misp-logo.png "MISP")

The MISP threat sharing platform is a free and open source software helping information sharing of threat intelligence including cyber security indicators.

MISP is a threat intelligence platform for gathering, sharing, storing and correlating Indicators of Compromise of targeted attacks, threat intelligence, financial fraud information, vulnerability information or even counter-terrorism information.

Many organizations use MISP to maintain internal repository of IOCs involved in any security incident of the organization.

MISP has rich RESTful API support to integrate with any producers or consumers of threat intelligence information.

### Requirements:

 - Python 3 
 - Packages in `requirements.txt`
 
### Installation:
```sh
git clone https://github.com/karthikkbala/MISP-QRadar-Integration.git
cd MISP-QRadar-Integration
pip3 install -r requirements.txt
```

### Configuration:

Edit the config.ini file with favourite editor and provide the following information.

```ini
[general]
misp_auth_key = mxVt2yZWkS39XemrgtyhbfYts7ZeeheQ50dXKLHO
misp_tag_filter = tlp:white,tlp:green
misp_category_filter = Network activity,Payload delivery,Artifacts dropped,Payload installation,Persistence mechanism
misp_server = <FQDN or IP of MISP Server>

qradar_auth_key = 811aacf9-ef79-456h-98d4-5d27b7a94844
qradar_server = <FQDN or IP of QRadar Server>

# In minutes
frequency = 60
# Only load new attributes since the last interval
fetch_incremental = True

[refset_attributes]
# Map which MISP attributes (e.g. url, dst-ip, src-ip, domain) to copy into which reference set
MISP_IP_IOC = ip-dst,ip-src
MISP_Host_IOC = domain,hostname,domain
MISP_Url_IOC = url,uri
MISP_Filehash_IOC = md5,sha1,sha256
```

### Usage:
```sh
python3 integration.py >> /var/log/misp-integration.log &
```

### Error Handling - Use Cases
 - Validate if the reference sets exist
 - Identify the Element Type of the reference set
 - Socket connection validation for QRadar and MISP

### Output - Success

```
14:55:04 -- Checking HTTPS Connectivity to QRadar
14:55:04 -- (Success) HTTPS Connectivity to QRadar
14:55:04 -- Checking HTTPS Connectivity to MISP
14:55:04 -- (Success) HTTPS Connectivity to MISP
14:55:05 -- Validating if reference set MISP_IP_IOC exists
14:55:05 -- Validating reference set MISP_IP_IOC - (Success)
14:55:05 -- Identifying Reference set MISP_IP_IOC element type
14:55:05 -- Reference set element type = IP (Success)
14:55:05 -- Initiating, GET data from MISP on <IP Address of MISP Server> since 2019-03-28
14:55:07 -- MISP API Query (Success)
14:55:07 -- 8 IOCs imported into MISP_IP_IOC
14:55:07 -- Initiating, IOC POST to QRadar
14:55:08 -- (Finished) Imported 8 IOCs to QRadar (Success)
14:55:08 -- Validating if reference set MISP_Domain_IOC exists
14:55:08 -- Validating reference set MISP_Domain_IOC - (Success)
14:55:08 -- Identifying Reference set MISP_Domain_IOC element type
14:55:08 -- Reference set element type = ALNIC (Success)
14:55:08 -- Initiating, GET data from MISP on <IP Address of MISP Server> since 2019-03-28
14:55:10 -- MISP API Query (Success)
14:55:10 -- 4 IOCs imported into MISP_Domain_IOC
14:55:10 -- Initiating, IOC POST to QRadar
14:55:10 -- (Finished) Imported 4 IOCs to QRadar (Success)
14:55:10 -- Validating if reference set MISP_URL_IOC exists
14:55:10 -- Validating reference set MISP_URL_IOC - (Success)
14:55:10 -- Identifying Reference set MISP_URL_IOC element type
14:55:10 -- Reference set element type = ALNIC (Success)
14:55:10 -- Initiating, GET data from MISP on <IP Address of MISP Server> since 2019-03-28
14:55:12 -- MISP API Query (Success)
14:55:12 -- 11 IOCs imported into MISP_URL_IOC
14:55:12 -- Initiating, IOC POST to QRadar
14:55:13 -- (Finished) Imported 11 IOCs to QRadar (Success)
```
