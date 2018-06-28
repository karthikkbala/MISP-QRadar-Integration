import requests
import json
import sys
import time
import re
import socket
import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#------*****------#

misp_auth_key = "H23CE6eC3BYCGKJGJG67892vArAY7GmqNN2nGI"
qradar_auth_key = "811aacf9-jh68-444h-98f4-5d25b7a94844"
qradar_ref_set = "MISP_Event_IOC"
misp_server = "MISP Server IP"
qradar_server = "QRadar Server IP"
frequency = 60 # In minutes

#------*****------#

misp_url = "https://" + misp_server + "/attributes/restSearch/json/null/"
QRadar_POST_url = "https://" + qradar_server + "/api/reference_data/sets/bulk_load/" + qradar_ref_set

MISP_headers = {
    'authorization': misp_auth_key,
    'cache-control': "no-cache",
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
        if refSet_etype == "IP":
            print (time.strftime("%H:%M:%S") + " -- " + "The QRadar Reference Set " + qradar_ref_set + " Element Type = \"IP\". Only IPs will be imported to QRadar and the other IOC types will be discarded")
            get_misp_data(refSet_etype)
        else:
            get_misp_data(refSet_etype)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "QRadar Reference Set does not exist, please verify if reference set exists in QRadar.")
        sys.exit()

def get_misp_data(refSet_etype):
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, GET data from MISP on " + misp_server)
    misp_response = requests.request('GET', misp_url, headers=MISP_headers, verify=False)
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
        if refSet_etype == "IP":
            print(time.strftime("%H:%M:%S") + " -- " + "Trying to clean the IOCs to IP address, as " + qradar_ref_set + " element type = IP")
            r = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            ioc_cleaned = list(filter(r.match, ioc_list))
            ioc_cleaned_data = json.dumps(ioc_cleaned)
            ioc_count_cleaned = len(ioc_cleaned)
            print(time.strftime("%H:%M:%S") + " -- " + "(Success) Extracted " + str(ioc_count_cleaned) + " IPs from initial import.")
            qradar_post_IP(ioc_cleaned_data, ioc_count_cleaned)
        else:
            qradar_post_all(import_data, ioc_count)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Failed), Please check the network connectivity")
        sys.exit()

def qradar_post_IP(ioc_cleaned_data, ioc_count_cleaned):
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to QRadar ")
    qradar_response = requests.request("POST", QRadar_POST_url, data=ioc_cleaned_data, headers=QRadar_headers, verify=False)
    if qradar_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "Imported " + str(ioc_count_cleaned) + " IOCs to QRadar (Success)" )
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not POST IOCs to QRadar (Failure)")

def qradar_post_all(import_data, ioc_count):
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to QRadar ")
    qradar_response = requests.request("POST", QRadar_POST_url, data=import_data, headers=QRadar_headers, verify=False)
    if qradar_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + " (Finished) Imported " + str(ioc_count) + " IOCs to QRadar (Success)" )
        print(time.strftime("%H:%M:%S") + " -- " + "Waiting to next schedule in " + schedule + "minutes")
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
scheduler.add_job(socket_check_qradar, 'interval', minutes=frequency, next_run_time=datetime.datetime.now())
scheduler.start()
