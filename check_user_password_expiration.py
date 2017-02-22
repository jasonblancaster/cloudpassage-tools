#!/usr/bin/env python2.7
# check_user_password_expiration.py


'''
    This will check local linux user accounts on servers protected with Halo to
    ensure they have the proper password expiration settings.
'''

__author__ = 'Jason B. Lancaster'
__email__ = 'jblancaster@gmail.com'
__license__ = 'GPL'
__version__ = '0.1'

import json
import cloudpassage


def create_api_session(session):
    config_file_loc = "cloudpassage.yaml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)

    return session

def get_server_accounts(api_session, server_id):
    hh = cloudpassage.HttpHelper(api_session)
    url = "/v1/servers/%s/accounts" % (server_id)

    return hh.get(url)


def get_account_details(api_session, server_id, username):
    hh = cloudpassage.HttpHelper(api_session)
    url = "/v1/servers/%s/accounts/%s" % (server_id, username)

    return hh.get(url)


def list_servers(api_session):
    server = cloudpassage.Server(api_session)
    list_of_servers = server.list_all(state='active')

    return list_of_servers


def main():
    api_session = None
    api_session = create_api_session(api_session)
    expiration_days = 90
    print("Checking Halo for user accounts with password expiration > %s days." % expiration_days)
    list_of_servers = list_servers(api_session)
    account_count = 0
    for server in list_of_servers:
        server_id = server['id']
        server_accounts = get_server_accounts(api_session, server_id)['accounts']
        print("Checking server: %s" % server['hostname'])
        for account in server_accounts:
            account_count += 1
            username = account['username']
            account_details = get_account_details(api_session, server_id, username)
            maximum_days_between_password_changes = int(account_details['account']['maximum_days_between_password_changes'])
            account_active = account_details['account']['active']
            if maximum_days_between_password_changes > expiration_days and account_active:
                print("WARNING: User account %s on server %s password expiration set to %s, > %s days." % \
                (username, server['hostname'], maximum_days_between_password_changes, expiration_days))
    print("Complete. %s accounts checked." % account_count)


if __name__ == "__main__":
    main()
