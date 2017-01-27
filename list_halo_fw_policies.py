#!/usr/bin/env python2.7
#
# Pull list of Halo FW policies for your account

import urllib
import httplib
import base64
import json
from datetime import date
import os.path
import cloudpassage

def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session


def get_halo_groups(api_session):
    list_of_groups = []
    group = cloudpassage.ServerGroup(api_session)
    list_of_groups = group.list_all()
    return list_of_groups


def get_fw_pol():
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)

    clientid = config_info.key_id
    clientsecret = config_info.secret_key
    host = 'api.cloudpassage.com'
    # Get the access token used for the API calls.
    connection = httplib.HTTPSConnection(host)
    authstring = "Basic " + base64.b64encode(clientid + ":" + clientsecret)
    header = {"Authorization": authstring}
    params = urllib.urlencode({'grant_type': 'client_credentials'})
    connection.request("POST", '/oauth/access_token', params, header)
    response = connection.getresponse()
    jsondata =  response.read().decode()
    data = json.loads(jsondata)
    key = data['access_token']

    # Do the real request using the access token in the headers
    tokenheader = {"Authorization": 'Bearer ' + key}
    connection.request("GET", "/v1/firewall_policies", '', tokenheader)
    response = connection.getresponse()
    jsondata =  response.read().decode()
    data = json.loads(jsondata)
    connection.close()
    return data

def get_fw_rules(api_session, fw_policies):
    fw_rules = []
    for fw_pol in fw_policies:
    	fw_pol_id = fw_pol['id']
        fw_pol_name = fw_pol['name']
        print (" FW Policy ID: %s \n FW Policy Name: %s" % (fw_pol_id, fw_pol_name))
        fw = cloudpassage.FirewallRule(api_session)
        fw_rules = fw.list_all(fw_pol_id)

    return fw_rules


def parse_fw_rules(api_session, fw_rules, dst_group, filename):
    results = []

    print ("\tWriting output to %s." % filename)
    with open(filename, 'a') as f:
        for each_rule in fw_rules:
            # Only include fw rules that are active and permit traffic
            if each_rule['active'] == True and each_rule['action'] == 'ACCEPT':
                if 'firewall_source' in each_rule:
                    src_group = each_rule['firewall_source']['name']
                else:
                    src_group = 'Any'

                dst_protocol = 'Any'
                dst_port = 'Any'

                if 'firewall_service' in each_rule:
                    if 'protocol' in each_rule['firewall_service']:
                        dst_protocol = each_rule['firewall_service']['protocol']
                    else:
                        dst_protocol = 'Any'
                    if 'port' in each_rule['firewall_service']:
                        dst_port = each_rule['firewall_service']['port']
                    else:
                        dst_port = 'Any'

                #print ("\t\t%s,%s:%s_%s,%s" % (src_group,dst_group,dst_protocol,dst_port,dst_group))
                f.write("%s,%s:%s_%s,%s\n" % (src_group,dst_group,dst_protocol,dst_port,dst_group))

    #return (src_group, dst_protocol, dst_port)


def main():
    api_session = None
    api_session = create_api_session(api_session)

    filename_custom = "_Halo_FW_Rules.csv"
    filename = str(date.today()) + filename_custom
    filename_version = 0
    while os.path.exists(filename):
        filename = ("%s.%s%s" % (date.today(),filename_version,filename_custom))
        filename_version += 1

    # List Halo groups
    list_of_groups = get_halo_groups(api_session)
    for group in list_of_groups:
        print("Group name: %s\tGroup ID: %s" % (group['name'], group['id']))
        print("\tWindows FW Policy: %s\n\tLinux FW policy: %s" % (group['windows_firewall_policy_id'], group['linux_firewall_policy_id']))
        dst_group = group['name']
        fw = cloudpassage.FirewallRule(api_session)
        # Parse each rule and write to file
        if group['linux_firewall_policy_id']:
            linux_fw_id = group['linux_firewall_policy_id']
            linux_fw_policy_rules = fw.list_all(linux_fw_id)
            parse_fw_rules(api_session, linux_fw_policy_rules, dst_group, filename)
        if group['windows_firewall_policy_id']:
            windows_fw_id = group['windows_firewall_policy_id']
            windows_fw_policy_rules = fw.list_all(windows_fw_id)
            parse_fw_rules(api_session, windows_fw_policy_rules, dst_group, filename)


if __name__ == "__main__":
    main()
