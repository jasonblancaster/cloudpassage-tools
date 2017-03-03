#!/usr/bin/env python2.7
# list_fim_changes.py

'''
    This will pull FIM event details from Halo via API. It itterates through
    all servers and writes changed files to a file.
    Requires the CloudPassage SDK. Put API key in the cloudpassage.yaml file.
'''

__author__ = 'Jason B. Lancaster'
__email__ = 'jblancaster@gmail.com'
__license__ = 'GPL'
__version__ = '0.1'


import cloudpassage
import json, csv, sys
import argparse
from datetime import date, timedelta, datetime


def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session


def get_args(argv=None):
    parser = argparse.ArgumentParser(description="Check CloudPassage Halo for CVE coverage.")
    parser.add_argument("-t", "--time", help="Enter number of days back to report on. Default: 1")

    return parser.parse_args(argv)


def listEvents(session, server_id, search_time):
    '''
    event types etailed here: https://api-doc.cloudpassage.com/help#event-types
    '''
    event_types = 'fim_target_integrity_changed'
    event = cloudpassage.Event(session)
    fim_events = event.list_all(1, server_id=server_id, type=event_types, since=search_time) # list_all first parameter is results *10 to return

    return fim_events


def scan_findings(api_session, scan_id, findings_id):
    scan = cloudpassage.Scan(api_session)
    scan_finding = scan.findings(scan_id, findings_id)

    return scan_finding


def listServers(session):
    """List the active servers in the Halo account."""

    server = cloudpassage.Server(session)
    list_of_servers = server.list_all(state='active')

    return list_of_servers


def convert_datetime(timestamp):
    timestamp_formatted = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    return timestamp_formatted


def write_csv(filename, fail_by_server):
    with open(filename, 'w') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['server_hostname', 'file_path', 'event_name', 'event_created', 'mtime'])
        for server_id in fail_by_server:
            for finding in fail_by_server[server_id]:
                findings = fail_by_server[server_id][finding]
                writer.writerow([findings['server_hostname'],
                findings['file_path'],
                findings['event_name'],
                findings['event_created'],
                findings['mtime']
                ])

def main():

    header = ("#"*80+"\n                     C  L  O  U  D  P  A  S  S  A  G  E \n"+"#"*80)
    argvals = None             # init argv in case not testing
    args = get_args(argvals)
    days_to_subtract = 1
    if args.time:
        days_to_subtract = int(args.time)
    search_time = datetime.today() - timedelta(days=days_to_subtract)
    api_session = None
    api_session = create_api_session(api_session)

    filename_custom = "_FIM_Report.csv"
    filename = str(date.today()) + filename_custom
    startTime = datetime.now()
    fail_by_server = {}
    # Get list of servers available to API key
    list_of_servers = listServers(api_session)
    print header
    print "Getting FIM findings per server..."
    # Pull FIM events for each server
    for serv in list_of_servers:
        server_id = serv["id"]
        serverHostname = serv["hostname"]
        fim_events = listEvents(api_session, server_id, search_time)
        print('%s: %s' % (serverHostname, len(fim_events)))
        # Parse events and get details
        for event in fim_events:
            server_hostname = event['server_hostname']
            event_created = event['created_at']
            event_created = datetime.strptime(event_created, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M')
            event_type = event['type']
            event_name = event['name']
            scan_id = event['scan_id']
            findings_id = event['finding_id']
            findings = scan_findings(api_session, scan_id, findings_id)['findings']
            for finding in findings:
                file_path = finding['file']
                if 'meta' in finding['detail']:
                    if 'mtime' in finding['detail']['meta']:
                        mtime = convert_datetime(finding['detail']['meta']['mtime'])
                    else:
                        mtime = None
                else:
                    mtime = None
            # Create event with detail, dedupe in the process
            if event['server_id'] not in fail_by_server:
                fail_by_server[event['server_id']] = {file_path: {"server_hostname": server_hostname,
                                                        "file_path": file_path,
                                                        "event_created": event_created,
                                                        "event_name": event_name,
                                                        "mtime": mtime}}
            elif file_path not in fail_by_server[event['server_id']]:
                fail_by_server[event['server_id']][file_path] = {"server_hostname": server_hostname,
                                                        "file_path": file_path,
                                                        "event_created": event_created,
                                                        "event_name": event_name,
                                                        "mtime": mtime}

    write_csv(filename, fail_by_server)
    print ("Complete. Report written to %s." % filename)

if __name__ == "__main__":
    main()
