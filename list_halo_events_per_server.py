#! /usr/local/bin/python

# Author: Jason Lancaster
# List all servers and issues

import json
import cloudpassage

def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session

def listEvents(session, serverID):
        event = cloudpassage.Event(session)
        serverEvent = event.list_all(2, server_id=serverID) # list_all first parameter is results *10 to return
        for e in serverEvent:
            print e["created_at"] + "\t" + e["name"]

def listServers(session):
    """List the active and deactivated servers in the Halo account."""

    print "#"*36 + "  List servers and events.  " + "#"*36
    print "#"*100

    server = cloudpassage.Server(session)
    list_of_servers = server.list_all(state='active')

    for serv in list_of_servers:
        print "ID: %s Server Name: %s Group: %s State: %s"\
            % (serv["id"], serv["hostname"], serv["group_name"], serv["state"])
        serverID = serv["id"]
        listEvents(session, serverID)


def main():
    api_session = None
    api_session = create_api_session(api_session)

    listServers(api_session)

if __name__ == "__main__":
    main()
