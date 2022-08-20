import requests
from .required_packages import Validator, creds, policy, change_pass_after_time, get_userid_by_token, policy
from .ldapauth import get_userInfo, config, ldap, getUserDn
from .applications import get_data
import json
from optparse import Values
from flask import Flask, jsonify, request, Blueprint
from flask_swagger_ui import get_swaggerui_blueprint
from pymongo import MongoClient
import sys
import random
import ast


PASSWORD_REQUEST= Blueprint("password", __name__)

def airflowUpdateMail(mail, password):
    try:
        infos = creds.find_one({"type":"airflow"})
        URL = infos["url"] + "/api/v1/dags/update_axetag_mail/dagRuns"
        me = infos["value"]
        data = "{\"conf\": {\"email\":\""+mail+"\", \"password\":\""+password+"\"}, \"dag_run_id\": \""+"airflow_" + str(random.random()) +"\" }"
        headers = {'Content-Type': 'application/json', 'accept': 'application/json' }
        results = requests.post(URL, data, auth=(me["username"], me["password"]), headers=headers)
        if results.status_code == 200:
            return "ok"
        else:
            return "something went wrong"
    except Exception as err:
        return str(err)

@PASSWORD_REQUEST.route('/mail/update', methods=['POST'])
def update_pass():
    data = get_data()
    Rh = "RH"
    Admin = "Administrators"
    try:
        userid = get_userid_by_token()
        search_dn1 = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
        search_dn2 = config['LDAP_GROUP_DN'] +','+ config['LDAP_BASE_DN']
        ldap.search(search_dn2, '(member='+getUserDn(userid)+')')
        groups = []
        for entry in ldap.entries:
            group = ast.literal_eval(entry.entry_to_json())
            groups.append(group['dn'].split(",")[0].split("=")[1])
        Usermail = get_userInfo(search_dn1, userid)["mail"][0]
        if not policy(data["newPassword"]):
            return jsonify({"status":"failed", "message": "The password does not respect the password policy."}), 200
        if Rh.lower() in groups or Admin.lower() in groups:
            ret = airflowUpdateMail(data['email'], data['newPassword'])
            if ret == "ok":
                return jsonify({"status":"success", "message": "Password update by admin process..."}), 200
            else:
                return jsonify({"status":"failed", "message": "Something went wrong"}), 400
        else:
            if data['email'] != Usermail:
                return jsonify({"status":"failed", "message": "Action not possible. You can only change your own password."}), 400
            elif data['email'] == Usermail:
                ret = airflowUpdateMail(data['email'], data['newPassword'])
                if ret == "ok":
                    return jsonify({"status":"success", "message": "Password update by user process..."}), 200
                else:
                    return jsonify({"status":"failed", "message": "Something went wrong"}), 400
            else:
                return jsonify({"status":"failed", "message": "Something went wrong"}), 400
    except Exception:
        return jsonify({"error": Exception}),400