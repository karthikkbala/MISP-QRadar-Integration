import requests
import json
import sys
import time
import re
import socket
from datetime import datetime, timedelta
from apscheduler.schedulers.blocking import BlockingScheduler
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#------*****------#

misp_auth_key = "mxVt2yZWkS39XemrgtyhbfYts7ZeeheQ50dXKLHO"
misp_types = ["ip-dst"] # Define attribute types that should be retrieved
misp_server = "FQDN or IP of MISP Server"

qradar_auth_key = "811aacf9-ef79-456h-98d4-5d27b7a94844"
qradar_ref_set = "MISP_Event_IOC"
qradar_server = "FQDN or IP of QRadar Server"

frequency = 60 # In minutes
fetch_incremental = True # Only load new attributes since the last interval

#------*****------#


misp_url = "https://" + misp_server + "/attributes/restSearch"
QRadar_POST_url = "https://" + qradar_server + "/api/reference_data/sets/bulk_load/" + qradar_ref_set

MISP_headers = {
    'authorization': misp_auth_key,
    'cache-control': "no-cache",
    'accept': "application/json",
    'content-type': "application/json",
}
MISP_request = {
    "returnFormat": "json",
    "type": {
        "OR": misp_types
    },
    "tags": {
        "OR": [
            "tlp:white",
            "tlp:green"
        ]
    },
    "published": True,
    "enforceWarninglist": True,
}

QRadar_headers = {
    'sec': qradar_auth_key,
    'content-type': "application/json",
}

def validate_refSet():
    validate_refSet_url = "https://" + qradar_server + "/api/reference_data/sets/" + qradar_ref_set
    validate_response = requests.request("GET", validate_refSet_url, headers=QRadar_headers, verify=False)
    print (time.strftime("%H:%M:%S") + " -- " + "Validating if reference set " + qradar_ref_set + " exists")
    if validate_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "Validating reference set " + qradar_ref_set + " - (Success) ")
        validate_response_data = validate_response.json()
        refSet_etype = (validate_response_data["element_type"])
        print(time.strftime("%H:%M:%S") + " -- " + "Identifying Reference set " + qradar_ref_set + " element type")
        print(time.strftime("%H:%M:%S") + " -- " + "Reference set element type = " + refSet_etype + " (Success) ")
        get_misp_data(refSet_etype)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "QRadar Reference Set does not exist, please verify if reference set exists in QRadar.")
        sys.exit()

def get_misp_data(refSet_etype):
    getAnnouncement = time.strftime("%H:%M:%S") + " -- " + "Initiating, GET data from MISP on " + misp_server
    if fetch_incremental:
        inc_time = datetime.today() - timedelta(minutes=frequency)
        MISP_request["from"] = inc_time.strftime("%Y-%m-%d")
        print(getAnnouncement + " since " + MISP_request["from"])
    else:
        print(getAnnouncement + " since account creation")

    misp_response = requests.request('POST', misp_url, json=MISP_request, headers=MISP_headers, verify=False)
    json_data = misp_response.json()
    ioc_list = []
    if misp_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Success) ")
        for data in json_data["response"]["Attribute"]:
            iocs = (data['value'])
            ioc_list.append(iocs)
        import_data = json.dumps(ioc_list)
        ioc_count = len(ioc_list)
        print(time.strftime("%H:%M:%S") + " -- " + str(ioc_count) + " IOCs imported")
        qradar_post_all(import_data, ioc_count)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Failed), Please check the network connectivity")
        sys.exit()

def qradar_post_all(import_data, ioc_count):
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to QRadar ")
    qradar_response = requests.request("POST", QRadar_POST_url, data=import_data, headers=QRadar_headers, verify=False)
    if qradar_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "(Finished) Imported " + str(ioc_count) + " IOCs to QRadar (Success)" )
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not POST IOCs to QRadar (Failure)")

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
        validate_refSet()
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to MISP Server, Please check connectivity before proceeding.")

scheduler = BlockingScheduler()
scheduler.add_job(socket_check_qradar, 'interval', minutes=frequency, next_run_time=datetime.now())
scheduler.start()
