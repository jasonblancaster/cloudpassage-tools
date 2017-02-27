#!/usr/bin/env python2.7
# halo_quarantine_compromised_workload.py

''' This will monitor CloudPassage Halo for a new process on a worlkload. For each new process
    It will get the hash of the binary and check VirusTotal.
'''

__author__ = 'Jason B. Lancaster'
__email__ = 'jblancaster@gmail.com'
__license__ = 'GPL'
__version__ = '0.1'

'''
    Requires auditd to log new processes
        apt-get install auditd
        auditctl -a task,always
        ausearch -i -sc execve

    Requires VirusTotal API Key
        https://www.virustotal.com/en/documentation/public-api/
        Enter API key as vt_api_key under main()

'''
import cloudpassage, haloevents
import json
import time
import sys, re, requests

def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session


def parseEvents(api_session):

    list_of_servers_executables = []
    policy_name = 'Process Created'

    server_process_list = []
    list_of_server_events = get_events(api_session)
    event = list_of_server_events['events'][0]
    if 'policy_name' in event: event_policy_name = event['policy_name']
    if policy_name == event_policy_name:
        try:
            log_entry = event['original_log_entry']
            log_search = re.search('.*exe="(.*)"', log_entry)
            process_executable = log_search.group(1)
            serverID = event['server_id']
            print("Server ID: %s\tProcess created: %s" % (serverID, process_executable))
            server_process_list = [serverID, process_executable]
            list_of_servers_executables.append(server_process_list)
        except:
            print "Failed to get parsed event."

    return list_of_servers_executables


def event_queue():
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    events = haloevents.HaloEvents(config_info.key_id, config_info.secret_key)

    return events

def get_events(api_session):
    hh = cloudpassage.HttpHelper(api_session)
    url = "/v1/events?per_page=1&type=lids_rule_failed&server_platform=linux"

    return hh.get(url)


def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session


def create_fim_policy(api_session, fim_policy):
    # Create Halo FIM policy
    policy = cloudpassage.FimPolicy(api_session)
    try:
        fim_policy_id = policy.create(fim_policy)
        print("Created FIM Policy %s" % fim_policy_id)
    except:
        fim_policy_id = None
        print "Could not create FIM Policy in Halo."

    return fim_policy_id


def get_halo_group(api_session, serverID):
    server = cloudpassage.Server(api_session)
    group_id = server.describe(serverID)['group_id']

    return group_id


def get_group_fim_policies(api_session, group_id):
    group = cloudpassage.ServerGroup(api_session)
    group_fim_policies = group.describe(group_id)['fim_policy_ids']

    return group_fim_policies


def get_fim_policies(api_session):
    hh = cloudpassage.HttpHelper(api_session)
    url = "/v1/fim_policies"

    return hh.get(url)


def get_fim_pol_baselines(api_session,fim_policy_id):
    fim_pol = cloudpassage.FimBaseline(api_session)
    fim_baselines = fim_pol.list_all(fim_policy_id)

    return fim_baselines


def create_baseline(api_session, fim_policy_id, serverID):
    baseline = cloudpassage.FimBaseline(api_session)
    baseline_id = baseline.create(fim_policy_id, serverID, expires=1)

    return baseline_id


def get_fim_baseline(api_session, policy_id, baseline_id):
    hh = cloudpassage.HttpHelper(api_session)
    url = "/v1/fim_policies/%s/baselines/%s/details" % (policy_id, baseline_id)

    return hh.get(url)

def create_fim_rule(f):
# The suppress list contains regex matches for documentation and other
# files you won't want any sort of high-alert attention directed to
# in the event they change.
    suppress = ['^/usr/share/doc',
                '^/usr/share/man']
    fimrule = {"target": f,
               "description": "FIM rule to get hash for VT check",
               "active": True,
               "recurse": False,
               "critical": True,
               "alert": False,
               }
    for s in suppress:
        if re.search(s,f):
            fimrule["critical"] = False
            return fimrule
        else:
            pass
    return fimrule


def fim_policy_body(rule, serverID, process_name):
    policyname = ("fim_policy_%s%s" % (serverID, process_name))
    poldesc = "This FIM policy was auto-generated for " + serverID + "."
    policyout = {"fim_policy": {
                   "name": policyname,
                   "description": poldesc,
                   "platform": "linux",
                   "module": "fim",
                   "shared": True,
                   "rules": [rule]
                   }}

    return policyout


def parse_hash(scan_targets, process_executable):
    for target in scan_targets:
        objects = target['objects']
        for obj in objects:
            if obj['filename'] == process_executable:
                obj_hash = obj['contents']

    return obj_hash


def vt_scan_report_from_hash(vt_api_key, hash):
    time.sleep(15)
    hash_url = "https://www.virustotal.com/vtapi/v2/file/report"
    r = requests.post(hash_url, data = {"apikey": vt_api_key, "resource": hash})
    try:
        positives = json.loads(r.text)["positives"]
        total = json.loads(r.text)["total"]
        print("VT Scan Found %s out of %s scan engines detected hash %s." % (positives, total, hash))
    except:
        print("VT query failed.")
        positives = None

    return positives


def main():

    api_session = None
    api_session = create_api_session(api_session)
    vt_api_key = # Enter VirusTotal API key here

    while True:
        list_of_servers_executables = parseEvents(api_session)
        for list in list_of_servers_executables:
            obj_hash = None
            serverID = list[0]
            process_executable = list[1]
            process_name = process_executable.replace('/', '_')
            rule = create_fim_rule(process_executable)
            fim_policy = fim_policy_body(rule, serverID, process_name)
            fim_policy_id = create_fim_policy(api_session, fim_policy)
            if not fim_policy_id:
                print("FIM Policy exists")
                # If FIM Policy name already exists, we've done this before. Let's check how old the hash is.
                # If it's less than 1 hr old grab existing hash. Else, let's get a new one.
                group_id =  get_halo_group(api_session, serverID)   # Get Halo gorup ID for Server
                print('ServerID: %s\tHalo Group: %s\nGetting FIM Policies for Halo group.' % (serverID, group_id))
                # get fim baseline data for existing policy
                fim_policies = get_fim_policies(api_session)['fim_policies']
                for fim_policy in fim_policies:
                    fim_policy_name = fim_policy['name']
                    if fim_policy_name == ("fim_policy_%s%s" % (serverID, process_name)):
                        fim_policy_id = fim_policy['id']
                        fim_baselines = get_fim_pol_baselines(api_session, fim_policy_id)
                        for baseline in fim_baselines:
                            # If our server has a baseline scan, get baseline scan details
                            if serverID == baseline['server_id']:
                                baseline_id = baseline['id']
                                baseline_time = baseline['effective_at']
                                print("Server: %s\tBaseline Scan ID: %s\tScan time: %s" % (serverID, baseline_id, baseline_time))
                                scan_details = get_fim_baseline(api_session, fim_policy_id, baseline_id)
                                scan_targets = scan_details['baseline']['details']['targets']
                                obj_hash = parse_hash(scan_targets, process_executable)
                if obj_hash == None:
                    print "Failed to get hash"

            elif fim_policy_id:
                # If the fim policy was created assign serverID to baseline scan
                baseline_id = create_baseline(api_session, fim_policy_id, serverID)
                print("FIM Baseline Scan starting now. Waiting for results.")
                sleep = 30
                time.sleep(sleep)
                scan_details = get_fim_baseline(api_session, fim_policy_id, baseline_id)
                scan_targets = scan_details['baseline']['details']['targets']
                obj_hash = parse_hash(scan_targets, process_executable)

            elif obj_hash == None:
                print "Couldn't process object hash."

            print("binary: %s\thash: %s" % (process_executable, obj_hash))

            positive_detect = vt_scan_report_from_hash(vt_api_key, obj_hash)
            if positive_detect > 0:
                print "Malware found."


if __name__ == "__main__":
    main()
