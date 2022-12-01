#!/usr/bin/python

import sys
import urllib3
urllib3.disable_warnings()
import getopt
import getpass
import base64
import requests
from pprint import pprint

def usage():
    sys.stderr.write("Usage: ntap_bo_group.py [-h] [-c creds] -u user svm netapp\n")
    sys.stderr.write("-h | --help : Prints this message\n")
    sys.stderr.write("-c | --creds= : Put SVM creds on the CLI  Format: user:password\n")
    sys.stderr.write(r"-u | --user= : User to add to the group.  Format: DOMAIN\user")
    sys.stderr.write("\nsvm : SVM name of the CIFS server\n")
    sys.stderr.write('netapp : Name/IP of the NTAP cluster management LIF\n')
    exit(0)

def ntap_auth_headers(user, password):
    auth_s = user + ":" + password
    ntap_creds = base64.encodebytes(auth_s.encode()).decode().replace('\n', '')
    headers = {'authorization': "Basic " + ntap_creds,
               'content-type': "application/json",
               'accept': "application/json"}
    return(headers)

def ntap_api_call(func, host, api, headers, payload):
    url = "https://" + host + "/api" + api
#    print(url)
#    print(headers)
    if func == "get":
        resp = requests.get(url, headers=headers, verify=False).json()
    elif func == "post":
#        pprint(payload)
        resp = requests.post(url, headers=headers, json=payload, verify=False).json()
    try:
        print(resp['error']['message'])
    except:
        return(resp)
    exit(2)


if __name__ == "__main__":
    user = ""
    password = ""
    group_name = "BUILTIN\Backup Operators"
    member = ""

    required_privs = ['sebackupprivilege', 'serestoreprivilege', 'sechangenotifyprivilege']

    optlist, args = getopt.getopt(sys.argv[1:], 'hc:u:', ['--help', '--creds=', '--user='])
    for opt, a in optlist:
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')
        if opt in ('-u', '--user'):
            member = a

    try:
        (svm, host) = args
    except:
        usage()
    if user == "":
        user = input("NTAP Admin User: ")
    if password == "":
        password = getpass.getpass("NTAP Admin Password: ")
    headers = ntap_auth_headers(user, password)
    bo_privs = ntap_api_call("get", host,
                             "/protocols/cifs/users-and-groups/privileges?svm.name=" + svm + "&name=Backup%20Operators&fields=privileges&return_records=true&return_timeout=60", headers, '')
    pprint(bo_privs)
    for p in bo_privs['records'][0]['privileges']:
        if p in required_privs:
            required_privs.remove(p)
    if required_privs:
        print("Adding privileges: " + str(required_privs))
        payload = {'name': group_name,
                   'privileges': required_privs,
                   'svm': {'name': svm}
                   }
        resp = ntap_api_call('post', host,
                              "/protocols/cifs/users-and-groups/privileges?return_records=true", headers, payload)
    else:
        print("All privileges are present")
#        pprint(resp)
    if member:
        group_info = ntap_api_call('get', host,
                             '/protocols/cifs/local-groups?svm.name=' + svm + "&name=Backup%20Operators&fields=name,members,sid&return_records=true&return_timeout=60", headers, '')
#        pprint(group_info)
        in_group = False
        for gm in group_info['records'][0]['members']:
            if gm['name'].lower() == member:
                in_group = True
                break
        if in_group:
            print("User " + member + " is already in " + group_name)
        else:
            print("Adding " + member + " to group " + group_name)
            payload = {'records': [{'name': member}]}
            resp = ntap_api_call('post', host,
                                 "/protocols/cifs/local-groups/" + group_info['records'][0]['svm']['uuid'] + "/" + group_info['records'][0]['sid'] + "/members", headers, payload)
