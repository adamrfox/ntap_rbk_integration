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
    print("Usage goes here!")
    exit(0)

def dprint(message):
    if DEBUG:
        print(message)

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
    DEBUG = False
    role_name = "rubrik"

    rbk_role = {
        'DEFAULT': 'none',
        'version': 'readonly',
        'volume create': 'readonly',
        'volume snapshot create': 'all',
        'volume snapshot delete': 'all',
        'vserver cifs share create': 'readonly',
        'vserver export-policy': 'readonly'
    }

    optlist, args = getopt.getopt(sys.argv[1:], 'hn:c:D', ['--help', '--name=', '--creds-', '--DEBUG'])
    for opt, a in optlist:
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-n', '--name'):
            role_name = a
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
    try:
        (svm, host) = args
    except:
        usage()
    if user == "":
        python_input("User: ")
    if password == "":
        getpass.getpass("Password: ")
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

    for elem in rbk_role.keys():
        api = NaElement("security-login-role-create")
        api.child_add_string("role-name", role_name)
        api.child_add_string("command-directory-name",elem)
        api.child_add_string("access-level", rbk_role[elem])
        api.child_add_string("vserver", svm)
        dprint("Adding " + elem)
        result = netapp.invoke_elem(api)
        if result.results_status() == "failed":
            if result.results_errno() != "13130":
                print(result.sprintf())
