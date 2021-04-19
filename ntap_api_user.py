#!/usr/bin/python

from __future__ import print_function
import sys
import urllib3
urllib3.disable_warnings()
sys.path.append('./NetApp')
from NaServer import *
import ssl
import getopt
import getpass

def usage():
    sys.stderr.write("Usage: ntap_api_user.py [-h] [-u user] [-c creds] [-r role] [-p password] svm ntap\n")
    sys.stderr.write("-h | --help : Prints Usage\n")
    sys.stderr.write("-c | --creds : NetApp Credentials [user:password]\n")
    sys.stderr.write("-r | --role : Set role name [default: rubrik]\n")
    sys.stderr.write("-p | --passoword: Password for rubrik user on NetApp\n")
    sys.stderr.write("svm : The SVM on the NetApp to whcih the user will be added\n")
    sys.stderr.write("ntap : Nmame or IP of NetApp cluster management LIF\n")
    exit(0)

def python_input(message):
    if int(sys.version[0]) > 2:
        val = input(message)
    else:
        val = raw_input(message)
    return(val)

def ntap_set_err_check(out):
    if(out and (out.results_errno() != 0)) :
        r = out.results_reason()
        print("Connection to filer failed" + r + "\n")
        sys.exit(2)

def ntap_invoke_err_check(out):
    if(out.results_status() == "failed"):
            print(out.results_reason() + "\n")
            sys.exit(2)

if __name__ == "__main__":

    user = ""
    password = ""
    api_user_name = "rubrik"
    api_user_password = ""
    role_name = "rubrik"

    optlist, args = getopt.getopt(sys.argv[1:], 'hu:c:r:p:', ['--help', '--user=', '--creds=', '--role=', '--password='])
    for opt, a in optlist:
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-u', '--user'):
            api_user_name = a
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')
        if opt in ('-r', '--role'):
            role_name = a
        if opt in ('-p', '--password'):
            api_user_password = a
    try:
        (svm, host) = args
    except:
        usage()
    if user == "":
        user = python_input("NTAP User: ")
    if password == "":
        password = getpass.getpass("Password: ")
    if api_user_password == "":
        valid = False
        while not valid:
            api_user_password = getpass.getpass("Password for API user '" + api_user_name + "': ")
            pw_validate = getpass.getpass("Re-enter password: ")
            if api_user_password == pw_validate:
                valid = True
            else:
                print("Passwords do not match")
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    netapp = NaServer(host, 1, 130)
    out = netapp.set_transport_type('HTTPS')
    ntap_set_err_check(out)
    out = netapp.set_style('LOGIN')
    ntap_set_err_check(out)
    out = netapp.set_admin_user(user, password)
    ntap_set_err_check(out)

    api = NaElement("security-login-create")
    api.child_add_string("role-name", role_name)
    api.child_add_string("vserver", svm)
    api.child_add_string("application", "ontapi")
    api.child_add_string("authentication-method", 'password')
    api.child_add_string("user-name", api_user_name)
    api.child_add_string("password", api_user_password)
    result = netapp.invoke_elem(api)
    if result.results_status() == "failed":
        print(result.sprintf())
