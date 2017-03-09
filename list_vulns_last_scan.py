#! /usr/local/bin/python

# Author: Jason B. Lancaster

# List all servers and vulns from last scan
# This will connect to CloudPassage Halo API to retrieve data and output to file
# Your API key should be in the cloudpassage.yaml file.

import json, sys, csv
import cloudpassage
from datetime import date, timedelta, datetime
import argparse

def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session


def convert_to_pure_ascii(string_val):
   """Converts a string to make sure it only contains valid
   ASCII code values. If a string's length changes, then
   this function detects this and reports uses the flag:
   'length_changed' to reflect that it changed.
   """
   len_changed = False
   len_original = 0
   len_encoded = 0

   if isinstance(string_val, unicode):
       len_original = len(string_val)
       string_val = string_val.encode("ascii", "ignore")
       len_encoded = len(string_val)
       if len_original != len_encoded:
           len_changed = True
   else:
       string_val = str(string_val).encode("ascii", "ignore")

   return (string_val) #len_changed

def lastScan(session, serverID, serverHostname):
    scan = cloudpassage.Scan(session)
    serverScan = scan.last_scan_results(server_id=serverID, scan_type='sva')
    details = scan.scan_details(serverScan['scan']["id"])

    return details


def listServers(session):
    """List the active and deactivated servers in the Halo account."""

    server = cloudpassage.Server(session)
    list_of_servers = server.list_all(state='active')

    return list_of_servers


def get_args(argv=None):
    parser = argparse.ArgumentParser(description="Check CloudPassage Halo for \
        CVE coverage. By default will write report to csv.")
    parser.add_argument("-c", "--csv", help="Write report to CSV")
    parser.add_argument("-t", "--text", help="Write report to text file")

    return parser.parse_args(argv)


def main():
    argvals = None             # init argv in case not testing
    args = get_args(argvals)
    api_session = None
    api_session = create_api_session(api_session)
    startTime = datetime.now()

    print "           C  L  O  U  D  P  A  S  S  A  G  E "
    print "Creating Vulnerability Report..."
    list_of_servers = listServers(api_session)

    if args.text:
        filename_custom = "_Vulnerability_Report.txt"
        filename = str(date.today()) + filename_custom
        with open(filename, 'w') as f:

            f.write("#"*122 + "\n")
            f.write("#"*42 + "   List servers and vulnerabilities.  " + "#"*42 + "\n")
            f.write("#"*122 + "\n")
            f.write("                                      ~     C  L  O  U  D  P  A  S  S  A  G  E     ~ \n")
            for serv in list_of_servers:
                f.write("#"*122 + "\n")
                f.write("IP: %s \tServer Name: %s \n OS: %s \tVersion: %s \n Halo Group: %s \tHalo Agent State: %s \n"\
                    % (serv["interfaces"][0]["ip_address"], serv["hostname"], serv["platform"], serv["platform_version"], serv["group_name"], serv["state"]))
                #print json.dumps(serv, indent=4)  # uncomment this if you want to see the full json data available to add more output
                serverID = serv["id"]
                serverHostname = serv["hostname"]
                details = lastScan(api_session, serverID, serverHostname)
                if details:
                    f.write(" Vulnerability scan completed: %s \n Critical Findings: %s \n" \
                    % (details["analysis_completed_at"], details["critical_findings_count"]))
                    print("Server: %s \t Critical vulnerabilities: %s") \
                    % (serv["interfaces"][0]["ip_address"], details["critical_findings_count"])
                    findings = details["findings"]
                    for vuln in findings:
                        if vuln["status"] == 'bad':
                            package_name = convert_to_pure_ascii(vuln["package_name"])
                            f.write("\tVulnerable package: %s \t Package version: %s \n" \
                            % (package_name, vuln["package_version"]))
                            cves = vuln["cve_entries"]
                            for cve in cves:
                                f.write("\t\tCVE: %s \t CVSS: %s \tRef: https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s\n" \
                                % (cve["cve_entry"], cve["cvss_score"], cve["cve_entry"]))
                else:
                    f.write("No SVA scan results for %s. \n" % (serverHostname))

    else:
        filename_custom = "_Vulnerability_Report.csv"
        filename = str(date.today()) + filename_custom
        list_of_servers = listServers(api_session)
        with open(filename, 'w') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['server_ip', 'serverHostname', \
                'server_os', 'server_os_version', 'server_group', \
                'server_state', 'halo_sva_scan_time', \
                'package_name', 'package_ver', 'cve_id', \
                'cvss_score', 'cve_ref'])
            for serv in list_of_servers:
                serverID = serv["id"]
                server_ip = serv["interfaces"][0]["ip_address"]
                serverHostname = serv["hostname"]
                server_os = serv["platform"]
                server_os_version = serv["platform_version"]
                server_group = serv["group_name"]
                server_state = serv["state"]

                details = lastScan(api_session, serverID, serverHostname)
                if details:
                    halo_sva_scan_time = datetime.strptime(\
                        details["analysis_completed_at"], \
                        '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M')
                    #print("#"*100)
                    print("Server: %s \t Critical vulnerabilities: %s") \
                    % (serv["interfaces"][0]["ip_address"], details["critical_findings_count"])
                    findings = details["findings"]
                    for vuln in findings:
                        if vuln["status"] == 'bad':
                            package_name = convert_to_pure_ascii(vuln["package_name"])
                            package_ver = vuln["package_version"]
                            #print("{:40}{}".format(package_name, package_ver))
                            cves = vuln["cve_entries"]
                            for cve in cves:
                                cve_id = cve["cve_entry"]
                                cvss_score = cve["cvss_score"]
                                cve_ref = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cve["cve_entry"]
                                writer.writerow([server_ip, serverHostname, \
                                    server_os, server_os_version, server_group, \
                                    server_state, halo_sva_scan_time, \
                                    package_name, package_ver, cve_id, \
                                    cvss_score, cve_ref])
            print ("Complete. Report written to %s." % filename)

    print "Report creation time: " + str(datetime.now() - startTime)


if __name__ == "__main__":
    main()
