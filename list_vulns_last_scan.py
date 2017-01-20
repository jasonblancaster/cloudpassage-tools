#! /usr/local/bin/python

# Author: Jason B. Lancaster

# List all servers and vulns from last scan
# This will connect to CloudPassage Halo API to retrieve data and output to file
# Your API key should be in the cloudpassage.yaml file

import json
import cloudpassage
from datetime import date, timedelta, datetime

def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session


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

def main():
    api_session = None
    api_session = create_api_session(api_session)

    filename_custom = "_Vulnerability_Report.txt"
    filename = str(date.today()) + filename_custom
    startTime = datetime.now()
    with open(filename, 'w') as f:

        f.write("#"*122 + "\n")
        f.write("#"*42 + "   List servers and vulnerabilities.  " + "#"*42 + "\n")
        f.write("#"*122 + "\n")
        f.write("                                      ~     C  L  O  U  D  P  A  S  S  A  G  E     ~ \n")
        print "           C  L  O  U  D  P  A  S  S  A  G  E "
        print "Creating Vulnerability Report..."

        list_of_servers = listServers(api_session)

        for serv in list_of_servers:

            f.write("#"*122 + "\n")
            f.write("IP: %s \tServer Name: %s \n OS: %s \tVersion: %s \n Halo Group: %s \tHalo Agent State: %s \n"\
                % (serv["interfaces"][0]["ip_address"], serv["hostname"], serv["platform"], serv["platform_version"], serv["group_name"], serv["state"]))
            #print serv  # uncomment this if you want to see the full json data available to add more output
            serverID = serv["id"]
            serverHostname = serv["hostname"]
            #scanDetails(session, serverID)
            details = lastScan(api_session, serverID, serverHostname)

            if details:
                f.write(" Vulnerability scan completed: %s \n Critical Findings: %s \n" \
                % (details["analysis_completed_at"], details["critical_findings_count"]))
                print("Server: %s \t Critical vulnerabilities: %s") \
                % (serv["interfaces"][0]["ip_address"], details["critical_findings_count"])
                findings = details["findings"]
                #print findings
                for vuln in findings:
                    if vuln["status"] == 'bad':

                        f.write("\tVulnerable package: %s \t Package version: %s \n" \
                        % (vuln["package_name"].encode('utf-8'), vuln["package_version"]))
                        cves = vuln["cve_entries"]
                        for cve in cves:
                            f.write("\t\tCVE: %s \t CVSS: %s \tRef: https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s\n" \
                            % (cve["cve_entry"], cve["cvss_score"], cve["cve_entry"]))
            else:
                f.write("No SVA scan results for %s. \n" % (serverHostname))

    print "Report creation time: " + str(datetime.now() - startTime)


if __name__ == "__main__":
    main()
