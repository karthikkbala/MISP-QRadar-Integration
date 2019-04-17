import requests
import json
import sys
import time
import re
import socket
import os
from datetime import datetime, timedelta
from apscheduler.schedulers.blocking import BlockingScheduler
from configparser import ConfigParser
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#------*****------#

config = ConfigParser()
config.optionxform = str 
config.read('config.ini')

misp_auth_key = config.get('general', 'misp_auth_key')
misp_tag_filter = config.get('general', 'misp_tag_filter').split(",")
misp_tag_blacklist = config.get('general', 'misp_tag_blacklist').split(",")
misp_category_filter = config.get('general', 'misp_category_filter').split(",")
misp_server = config.get('general', 'misp_server')

qradar_auth_key = config.get('general', 'qradar_auth_key')
qradar_server = config.get('general', 'qradar_server')

frequency = config.getint('general', 'frequency')
fetch_incremental = config.getboolean("general", "fetch_incremental")

# Read refset config
qradar_refset_from_misp_attribute = {}
for (each_key, each_val) in config.items("refset_attributes"):
    qradar_refset_from_misp_attribute[each_key] = each_val.split(",")

#------*****------#

# Define algorithms to normalize return values
stripProtocol = lambda x : re.sub("https?://", "", x)
misp_clean_attributes = {
	"url": stripProtocol,
	"uri": stripProtocol,
}

# Prebuild headers
MISP_headers = {
    'authorization': misp_auth_key,
    'cache-control': "no-cache",
    'accept': "application/json",
    'content-type': "application/json",
}
misp_tag_blacklist = ["!" + tag for tag in misp_tag_blacklist]
MISP_request = {
    "returnFormat": "json",
    "type": {
        "OR": None
    },
    "tags": {
		"AND": [
			{"AND": misp_tag_blacklist},
			{"OR": misp_tag_filter}
		]
        
    },
	"category": {
		"OR": misp_category_filter
	},
    "published": True,
    "enforceWarninglist": True,
}
QRadar_headers = {
    'sec': qradar_auth_key,
    'content-type': "application/json",
}

def validate_refSet(qradar_refset):
    validate_refSet_url = "https://" + qradar_server + "/api/reference_data/sets/" + qradar_refset
    validate_response = requests.request("GET", validate_refSet_url, headers=QRadar_headers, verify=False)
    print (time.strftime("%H:%M:%S") + " -- " + "Validating if reference set " + qradar_refset + " exists")
    if validate_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "Validating reference set " + qradar_refset + " - (Success) ")
        validate_response_data = validate_response.json()
        print(time.strftime("%H:%M:%S") + " -- " + "Identifying Reference set " + qradar_refset + " element type")
        print(time.strftime("%H:%M:%S") + " -- " + "Reference set element type = " + validate_response_data["element_type"] + " (Success) ")
        get_misp_data(qradar_refset)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "QRadar Reference Set does not exist, please verify if reference set exists in QRadar.")
        sys.exit()

def get_misp_data(qradar_refset):
    getAnnouncement = time.strftime("%H:%M:%S") + " -- " + "Initiating, GET data from MISP on " + misp_server
    if fetch_incremental:
        inc_time = datetime.today() - timedelta(minutes=frequency)
        MISP_request["from"] = inc_time.strftime("%Y-%m-%d")
        print(getAnnouncement + " since " + MISP_request["from"])
    else:
        print(getAnnouncement + " since account creation")

    MISP_request["type"]["OR"] = qradar_refset_from_misp_attribute[qradar_refset]
    misp_response = requests.request('POST', "https://" + misp_server + "/attributes/restSearch", json=MISP_request, headers=MISP_headers, verify=False)
    json_data = misp_response.json()
    ioc_list = []
    if misp_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Success) ")
        for data in json_data["response"]["Attribute"]:
            dataValue = data["value"]
            if data["type"] in misp_clean_attributes:
                dataValue = misp_clean_attributes[data["type"]](dataValue)

            iocs = (dataValue)
            ioc_list.append(iocs)
        import_data = json.dumps(ioc_list)
        ioc_count = len(ioc_list)
        print(time.strftime("%H:%M:%S") + " -- " + str(ioc_count) + " IOCs found for " + qradar_refset)
        qradar_post_all(qradar_refset, import_data, ioc_count)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Failure " + str(misp_response.status_code) + "), Please check the network connectivity")
        sys.exit()

def qradar_post_all(qradar_refset, import_data, ioc_count):
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to QRadar ")
    qradar_response = requests.request("POST", "https://" + qradar_server + "/api/reference_data/sets/bulk_load/" + qradar_refset, data=import_data, headers=QRadar_headers, verify=False)
    if qradar_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "(Finished) Imported " + str(ioc_count) + " IOCs to QRadar (Success)" )
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not POST IOCs to QRadar (Failure " + str(qradar_response.status_code) + ")")

def socket_check_qradar():
    print(time.strftime("%H:%M:%S") + " -- " + "Checking HTTPS Connectivity to QRadar")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((qradar_server, int(443)))

    if result == 0:
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) HTTPS Connectivity to QRadar")
        socket_check_misp()
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to QRadar, Please check connectivity before proceeding.")

def socket_check_misp():
    print(time.strftime("%H:%M:%S") + " -- " + "Checking HTTPS Connectivity to MISP")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((misp_server, int(443)))

    if result == 0:
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) HTTPS Connectivity to MISP")
        
        for qradar_refset, misp_attributes in qradar_refset_from_misp_attribute.items():
            validate_refSet(qradar_refset)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to MISP Server, Please check connectivity before proceeding.")

scheduler = BlockingScheduler()
scheduler.add_job(socket_check_qradar, 'interval', minutes=frequency, next_run_time=datetime.now())
scheduler.start()
