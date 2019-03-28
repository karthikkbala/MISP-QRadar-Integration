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

Edit the integration.py file with favourite editor and provide the following information.

```sh
misp_auth_key = "mxVt2yZWkS39XemrgtyhbfYts7ZeeheQ50dXKLHO"
misp_types = ["ip-dst"] # Define attribute types that should be retrieved
misp_server = "FQDN or IP of MISP Server"

qradar_auth_key = "811aacf9-ef79-456h-98d4-5d27b7a94844"
qradar_ref_set = "MISP_Event_IOC"
qradar_server = "FQDN or IP of QRadar Server"

frequency = 60 # In minutes
fetch_incremental = True # Only load new attributes since the last interval
```

### Usage:
```sh
python3 integration.py >> /var/log/misp-integration.log &
```

### Error Handling - Use Cases
 - Validate if the reference set exists
 - Identify the Element Type of the reference set
 - Socket connection validation for QRadar and MISP

### Output - Success

```
17:05:50 -- Checking HTTPS Connectivity to QRadar
17:05:50 -- (Success) HTTPS Connectivity to QRadar
17:05:50 -- Checking HTTPS Connectivity to MISP
17:05:50 -- (Success) HTTPS Connectivity to MISP
17:05:50 -- Validating if reference set MISP_Event_IOC exists
17:05:50 -- Validating reference set MISP_Event_IOC - (Success)
17:05:50 -- Identifying Reference set MISP_Event_IOC element type
17:05:50 -- Reference set element type = IP (Success)
17:05:50 -- Initiating, GET data from MISP on <IP Address of MISP Server> since 2019-03-15
17:05:51 -- MISP API Query (Success)
17:05:51 -- 36 IOCs imported
17:05:51 -- Initiating, IOC POST to QRadar
17:05:51 -- (Finished) Imported 36 IOCs to QRadar (Success)
```
