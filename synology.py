#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Updates Synology NAS SSL certificate for a certificate being renewed on a remote server

Usage: python3 /path/to/synology.py $RENEWED_LINEAGE/privkey.pem $RENEWED_LINEAGE/fullchain.pem
"""

import sys

import requests
from OpenSSL import crypto

__author__ = "Christopher Peterson"
__copyright__ = "Copyright 2020, Christopher Peterson"
__credits__ = ["Christopher Peterson"]
__license__ = "GNU GPLv3"
__version__ = "1.0"
__maintainer__ = "Christopher Peterson"
__email__ = "chris@bacon.industries"
__status__ = "Production"

base_url = ""
username = ""
password = ""

login_endpoint = "/webapi/auth.cgi"
login_query = {"api": "SYNO.API.Auth", "version": "3", "method": "login", "session": "Certificate", "format": "sid",
               "account": username, "passwd": password}
logout_query = {"api": "SYNO.API.Auth", "version": "3", "method": "logout"}

certificate_endpoint = "/webapi/entry.cgi"
list_certificates_query = {"api": "SYNO.Core.Certificate.CRT", "version": "1", "method": "list"}
update_certificate_query = {"api": "SYNO.Core.Certificate", "version": "1", "method": "import"}

cookies = {}


def update_certificate(private_key, fullchain):
    certificate_cn = crypto.load_certificate(crypto.FILETYPE_PEM, open(fullchain).read()).get_subject().CN

    login_response = requests.get(base_url + login_endpoint, params=login_query).json()
    if not login_response["success"]:
        print("Login failed")
        return False
    sid = str(login_response["data"]["sid"])

    for query_string in (logout_query, list_certificates_query, update_certificate_query):
        query_string["sid"] = sid
    cookies["id"] = sid

    certificate_list = requests.get(base_url + certificate_endpoint, params=list_certificates_query, cookies=cookies).json()
    if not certificate_list["success"]:
        print("Could not get certificates")
        return True

    certificate_id = None
    desc = None
    default = False
    for certificate in certificate_list["data"]["certificates"]:
        if certificate["subject"]["common_name"] == certificate_cn:
            certificate_id = str(certificate["id"])
            desc = certificate["desc"]
            default = certificate["is_default"]
            break
    else:
        print("Certificate not found on Synology")

    if certificate_id is not None:
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

        if not requests.post(base_url + certificate_endpoint, data=payload, files=files, params=update_certificate_query, cookies=cookies).json()["success"]:
            print("Updating certificate failed")

    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise ValueError("Path to private key and fullchain must be supplied")

    if update_certificate(sys.argv[1], sys.argv[2]) and not requests.get(base_url + login_endpoint, params=logout_query, cookies=cookies).json()["success"]:
        print("Logout failed")
