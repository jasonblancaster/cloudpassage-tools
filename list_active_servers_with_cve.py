#! /usr/local/bin/python

# Author: Jason Lancaster
# List all servers with entered CVE. Only active servers are returned.
# Search result is written to a file in the current directory with file name of the CVE.

import json, sys
import cloudpassage
from datetime import date, timedelta, datetime

def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session


def listServers(session, cve_search):
    server = cloudpassage.Server(session)
    list_of_servers = server.list_all(state='active', cve=cve_search)
    filename = cve_search + "_" + str(date.today()) + ".txt"
    startTime = datetime.now()
    with open(filename, 'w') as f:
        server_count = 0
        for serv in list_of_servers:
            f.write(serv["hostname"])
            f.write('\n')
            server_count = server_count +1
#    print "Search complete. " + str(server_count) + " servers found with " + cve_search + "."
    my_string = "Search complete. %s servers found with %s." % (str(server_count), cve_search)
    print(my_string)
    print "Search time: " + str(datetime.now() - startTime)


def main():
    api_session = None
    api_session = create_api_session(api_session)

    print "Enter CVE to search:"
    cve_search = str.upper(raw_input())
    print "Searching Halo for data..."
    listServers(api_session, cve_search)


if __name__ == "__main__":
    main()
