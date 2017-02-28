#!/usr/bin/env python2.7
# list_fim_change.py

'''
    This will pull FIM event details from Halo via API.
    Requires the CloudPassage SDK. Put API key in the cloudpassage.yaml file.
'''

__author__ = 'Jason B. Lancaster'
__email__ = 'jblancaster@gmail.com'
__license__ = 'GPL'
__version__ = '0.1'


import cloudpassage
import json, sys
import argparse


def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session


def get_group_id(api_session, group_name):
    list_of_groups = get_halo_groups(api_session)
    for group in list_of_groups:
        if group_name == group['name']:
            group_id = group['id']

    return group_id


def get_halo_groups(api_session):
    list_of_groups = []
    group = cloudpassage.ServerGroup(api_session)
    list_of_groups = group.list_all()

    return list_of_groups


def get_args(argv=None):
    parser = argparse.ArgumentParser(description="Check CloudPassage Halo for CVE coverage.")
    parser.add_argument("-g", "--search_groups", nargs='+', help="Search Halo events for listed groups. \
                        Enter groups in quotes.")
    parser.add_argument("-l", "--list_groups", action='store_true', help="List Halo groups.")

    return parser.parse_args(argv)


def listEvents(session, group_id):
    '''
    event types etailed here: https://api-doc.cloudpassage.com/help#event-types
    '''
    event_types = 'fim_target_integrity_changed'
    event = cloudpassage.Event(session)
    fim_events = event.list_all(1, group_id=group_id, type=event_types) # list_all first parameter is results *10 to return

    return fim_events


def scan_findings(api_session, scan_id, findings_id):
    scan = cloudpassage.Scan(api_session)
    scan_finding = scan.findings(scan_id, findings_id)

    return scan_finding

def main():

    header = ("#"*80+"\n                     C  L  O  U  D  P  A  S  S  A  G  E \n"+"#"*80)
    argvals = None             # init argv in case not testing
    args = get_args(argvals)

    api_session = None
    api_session = create_api_session(api_session)

    if args.list_groups:
        print header
        print "Available Halo Groups:"
        list_of_groups = get_halo_groups(api_session)
        for group in list_of_groups:
            print group['name']

    if args.search_groups:
        search_groups = args.search_groups
        print header
        print "Getting FIM Findings..."
        file_check = []
        for group_name in search_groups:
            print ("Halo Group: %s " % group_name)
            group_id = get_group_id(api_session, group_name)
            fim_events = listEvents(api_session, group_id)
            for event in fim_events:
                server_hostname = event['server_hostname']
                event_created = event['created_at']
                event_type = event['type']
                event_name = event['name']
                event_message = event['message']
                scan_id = event['scan_id']
                findings_id = event['finding_id']
                findings = scan_findings(api_session, scan_id, findings_id)['findings']
                for finding in findings:
                    file_path = finding['file']
                    if [server_hostname, file_path] not in file_check:
                        print '{:<28}{:<36}{:<20}{:<20}'.format(event_created, event_name, server_hostname, file_path)
                        file_check.append([server_hostname, file_path])
            print "\n"
    print "Complete."

if __name__ == "__main__":
    main()
