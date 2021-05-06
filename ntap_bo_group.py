#!/usr/bin/python
from __future__  import print_function
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
        print(message + "\n")


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

def add_priv_to_group(netapp,group_name, required_privs):
    api = NaElement("cifs-privilege-add-privilege")
    xi = NaElement("privileges")
    api.child_add(xi)
    for p in required_privs:
        print ("Adding " + p + " to the group")
        xi.child_add_string("cifs-privilege-entries", p)
    api.child_add_string("user-or-group-name", group_name)
    out = netapp.invoke_elem(api)
    if (out.results_status() == "failed"):
        print("Error:\n")
        print(out.sprintf())
        sys.exit(1)

def add_user_to_group(netapp, group_name, member):
    api = NaElement("cifs-local-group-members-add-members")
    api.child_add_string("group-name", group_name)
    xi = NaElement("member-names")
    api.child_add(xi)
    xi.child_add_string("cifs-name", member)
    out = netapp.invoke_elem(api)
    if (out.results_status() == "failed"):
        print("Error:\n")
        print(out.sprintf())
        sys.exit(1)

if __name__ == "__main__":
    user = ""
    password = ""
    group_name = "BUILTIN\Backup Operators"
    member = ""
    DEBUG = False

    required_privs = ['sebackupprivilege', 'serestoreprivilege', 'sechangenotifyprivilege']

    optlist, args = getopt.getopt(sys.argv[1:], 'hc:u:D', ['--help', '--creds=', '--user=', '--DEBUG'])
    for opt, a in optlist:
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')
        if opt in ('-u', '--user'):
            member = a
        if opt in ('-D', '--DEBUG'):
            DEBUG = True

    try:
        host = args[0]
    except:
        usage()
    if user == "":
        user = python_input("NTAP Admin User: ")
    if password == "":
        password = getpass.getpass("NTAP Admin Password: ")
    try:
         _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    netapp = NaServer(host, 1, 160)
    out = netapp.set_transport_type('HTTPS')
    ntap_set_err_check(out)
    out = netapp.set_style('LOGIN')
    ntap_set_err_check(out)
    out = netapp.set_admin_user(user, password)
    ntap_set_err_check(out)

    api = NaElement("cifs-privilege-get-iter")
    xi = NaElement("desired-attributes")
    api.child_add(xi)
    xi1 = NaElement("cifs-privilege")
    xi.child_add(xi1)
    xi2 = NaElement("privileges")
    xi1.child_add(xi2)
    xi2.child_add_string("cifs-privilege-entries", "<cifs-privilege-entries>")
    xi1.child_add_string("user-or-group-name", group_name)
#    xi1.child_add_string("vserver", svm)
    api.child_add_string("max-records", "100")
    xi3 = NaElement("query")
    api.child_add(xi3)
    out = netapp.invoke_elem(api)
    if (out.results_status() == "failed") :
        print ("Error:\n")
        print (out.sprintf())
        sys.exit (1)
    out_info = out.child_get("attributes-list").children_get()
    for cp_list in out_info:
        try:
            priv_list = cp_list.child_get("privileges").children_get()
        except AttributeError:
            break
        for priv in priv_list:
            priv_list = priv.sprintf()
            pl2 = priv_list.replace('<', '>')
            plf = pl2.split('>')
            if plf[2] in required_privs:
                required_privs.remove(plf[2])
    if required_privs:
        add_priv_to_group(netapp, group_name, required_privs)
    else:
        print("All required privileges are present")
    if member != "":
        api = NaElement("cifs-local-group-members-get-iter")
        xi = NaElement("desired-attributes")
        api.child_add(xi)
        xi1 = NaElement("cifs-local-group-members")
        xi.child_add(xi1)
        xi1.child_add_string("group-name", group_name)
        xi1.child_add_string("member", member)
#        xi1.child_add_string("vserver", svm)
        api.child_add_string("max-records", "100")
        xi2 = NaElement("query")
        api.child_add(xi2)
        out = netapp.invoke_elem(api)
        if (out.results_status() == "failed"):
            print("Error:\n")
            print(out.sprintf())
            sys.exit(1)
        group_list = out.child_get("attributes-list").children_get()
        empty_group = True
        for group in group_list:
            name = group.child_get_string("group-name")
            if name != group_name:
                continue
            empty_group = False
            membership = group.child_get_string("member")
            membership_list = membership.split()
            if member in membership_list:
                print("User " + member + " is alredy a member of " + group_name)
                exit(0)
            print("Adding " + member + " to " + group_name)
            add_user_to_group(netapp, group_name, member)
            break
        if empty_group:
            print("Adding " + member + " to " + group_name)
            add_user_to_group(netapp, group_name, member)


