#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Updates Synology NAS SSL certificate for a certificate being renewed on a remote server

Usage: python3 /path/to/synology.py $RENEWED_LINEAGE/privkey.pem $RENEWED_LINEAGE/fullchain.pem
"""

import sys

import requests
import urllib3
from OpenSSL import crypto

__author__ = "Christopher Peterson"
__copyright__ = "Copyright 2020, Christopher Peterson"
__credits__ = ["Christopher Peterson"]
__license__ = "GNU GPLv3"
__version__ = "1.1"
__maintainer__ = "Christopher Peterson"
__email__ = "chris@bacon.industries"
__status__ = "Production"

base_url = ""
username = ""
password = ""
ssl_verification = True

api_endpoint = base_url + "/webapi/entry.cgi"
login_query = {"api": "SYNO.API.Auth", "version": "3", "method": "login", "session": "Certificate", "format": "sid",
               "account": username, "passwd": password}
logout_query = {"api": "SYNO.API.Auth", "version": "3", "method": "logout"}
list_certificates_query = {"api": "SYNO.Core.Certificate.CRT", "version": "1", "method": "list"}
update_certificate_query = {"api": "SYNO.Core.Certificate", "version": "1", "method": "import"}


def login(session):
    login_response = session.get(api_endpoint, params=login_query).json()
    if login_response["success"]:
        sid = str(login_response["data"]["sid"])

        for query_string in (logout_query, list_certificates_query, update_certificate_query):
            query_string["sid"] = sid
        return True
    print("Login failed")
    return False


def logout(session):
    if not session.get(api_endpoint, params=logout_query).json()["success"]:
        print("Logout failed")


def get_synology_certificate_info(session, certificate_cn):
    certificate_id = None
    desc = None
    default = False

    certificate_list = session.get(api_endpoint, params=list_certificates_query).json()
    if certificate_list["success"]:
        for certificate in certificate_list["data"]["certificates"]:
            if certificate["subject"]["common_name"] == certificate_cn:
                certificate_id = str(certificate["id"])
                desc = certificate["desc"]
                default = certificate["is_default"]
                break
        else:
            print("Certificate not found on Synology", certificate_cn)
    else:
        print("Could not get certificates")

    return certificate_id, desc, default


def replace_synology_certificate(session, private_key, fullchain, certificate_id, desc, default):
    payload = {
        "id": certificate_id,
        "desc": desc
    }
    if default:
        payload["as_default"] = ""
    files = {
        "key": ("privkey.pem", open(private_key)),
        "cert": ("fullchain.pem", open(fullchain)),
        "inter_cert": None
    }

    if not session.post(api_endpoint, data=payload, files=files, params=update_certificate_query).json()["success"]:
        print("Updating certificate failed")


def update_certificate(private_key, fullchain):
    with requests.Session() as request_session:
        request_session.verify = ssl_verification
        if not ssl_verification:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if login(request_session):
            try:
                certificate_bytes = open(fullchain, "rb").read()
                certificate_cn = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_bytes).get_subject().CN
                certificate_id, desc, default = get_synology_certificate_info(request_session, certificate_cn)
                if certificate_id is not None:
                    replace_synology_certificate(request_session, private_key, fullchain, certificate_id, desc, default)
            finally:
                logout(request_session)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise ValueError("Path to private key and fullchain must be supplied")

    update_certificate(sys.argv[1], sys.argv[2])
