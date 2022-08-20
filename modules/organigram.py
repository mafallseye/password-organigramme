from genericpath import exists
import random
from textwrap import indent
from threading import Thread
import traceback
from xml.dom.pulldom import parseString
from flask import redirect, request,jsonify, Blueprint, json
import requests
from modules.required_packages import encode_token, fetchSons, get_userid_by_token, policy, run_dag, mail_sender, generate_code, tokenValidation, validMail, validation, encode_auth_token
from ldap3 import LEVEL, MODIFY_ADD, MODIFY_REPLACE, Server, Connection, ALL, SUBTREE, NTLM, HASHED_SALTED_SHA
from ldap3.utils.hashed import hashed
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups
import ast
import pymongo
import pyotp
import os
from bson import ObjectId
from datetime import datetime, timedelta

client = pymongo.MongoClient("mongodb://db002usr:Hav*1cha@10.0.0.185:27017")
db002 = client['db002']
creds = db002["creds"]
FA2 = db002["2FA"]
FA2info = db002["info2FA"]
tasks = db002["tasks"]
tokens = db002["tokens"]
profile_roles = db002["profile_roles"]
technical_profiles = db002["technical_profiles"]
users = db002["users"]
applications = db002["organigram_app"]
technical_profile_requests = db002["technical_profile_requests"]

airflow = creds.find_one({"type":"airflow"},{"_id":0})
tokSecret = creds.find_one({"type":"token_secret"})

ldap_server = creds.find_one({"type":"ldap"},{"_id":0})
profile_role_exp = creds.find_one({"type" : "expiration_date_role"})["delai"]
server = Server(ldap_server["url"], get_info=ALL)
ldap = Connection(
    server,
    user=ldap_server["value"]["default_user_dn"],
    password=ldap_server["value"]["default_password"]
)

ldapState = ldap.bind()
print(ldapState)
config = dict()
config['HOST'] = ldap_server["url"]
config['BASE_DN'] = ldap_server["value"]["base_dn"]
config['USER_DN'] = ldap_server["value"]["user_dn"]
config['GROUP_DN'] = ldap_server["value"]["group_dn"]
config['ROLE_MGR'] = ldap_server["value"]["profil_role_mgr"]
config['TECHNICAL_MGR'] = ldap_server["value"]["technical_profil_mgr"]
config['ROLE_VIEWER'] = ldap_server["value"]["profil_role_viewer"]
config['TECHNICAL_VIEWER'] = ldap_server["value"]["technical_profil_viewer"]

readonly_group = ldap_server["value"]["readonly"]

ORGANIGRAM_REQUEST = Blueprint('organigram_request', __name__)

def getUserDn(uid):
    DN ='uid=' + uid + ',' + config['USER_DN'] + ',' + config['BASE_DN']
    return DN

def getGroupDn(cn):#cn=readonly,ou=groups,dc=axetag,dc=com
    DN ='cn=' + cn + ',' + config['GROUP_DN'] + ',' + config['BASE_DN']
    return DN

def get_all_groups():
    search_dn = config['GROUP_DN'] +','+ config['BASE_DN']
    result = ldap.search(
        search_dn,
        '(objectClass=*)',
        search_scope=LEVEL,
        attributes=["cn"]
    )
    if result:
        roles = []
        for ldent in ldap.entries:
            srj_dict = ast.literal_eval(ldent.entry_to_json())["attributes"]["cn"][0]
            roles.append(srj_dict)
        return roles
    else:
        return None

def get_data():
    if not request.get_json():
        return None
    data = request.get_json(force=True)
    return data

def ldap_state():
    data = get_data()
    # server = Server("192.168.1.189:389", get_info=ALL)
    ldap = Connection(server, user=data["uid"], password=data["password"])
    ldapState =ldap.bind()
    return {"state":ldapState, "ldap":ldap}

def get_userInfo(search_dn, uid):
    ldap.search(
        search_dn,
        f'(&(objectclass=person)(uid={uid}))', 
        attributes = [
            'mail','homeDirectory','sn','uidNumber',
            'manager','cn','gidNumber','loginShell',
            'telephoneNumber','displayName','uid','businessCategory'
        ]
    )
    search_result_json = None if len(ldap.entries) == 0 else ldap.entries[0].entry_to_json()
    if search_result_json is None:
        return None
    srj_dict = ast.literal_eval(search_result_json)
    try: 
        return srj_dict["attributes"]
    except KeyError:
        return None

def updateAttributes(default, req_data):
    uid = req_data["uid"]
    user_dn = getUserDn(uid)
    for key, value in req_data.items():
        condition = value == None or value == ""
        
        if key == "firstname":
            default["cn"] = default["cn"] if condition else value
        if key == "lastname":
            default["sn"] = default["sn"] if condition else value
        if key == "email":
            default["mail"] = default["mail"] if condition else value
        if key == "tel":
            default["telephoneNumber"] = default["telephoneNumber"] if condition else value
        if key == "loginShell":
            default["loginShell"] = default["loginShell"] if condition else value

    for key, value in default.items():
        if type(value) == type(""):
            ldap.modify(user_dn, {key: [(MODIFY_REPLACE, [value])]})
         
    search_dn = config['USER_DN'] +','+ config['BASE_DN']       
    afterMod = get_userInfo(search_dn, uid)
    displayName = afterMod["cn"][0] + " " + afterMod["sn"][0]
    ldap.modify(user_dn, {"displayName": [(MODIFY_REPLACE, [displayName])]})

def getUserAttributes(uid, attrs):
    ldap.search(
        config['USER_DN'] +','+ config['BASE_DN'],
        f'(&(objectclass=person)(uid={uid}))', 
        attributes = attrs
    )
    search_result_json = None if len(ldap.entries) == 0 else ldap.entries[0].entry_to_json()
    if search_result_json is None:
        return None
    srj_dict = ast.literal_eval(search_result_json)
    try: 
        data = {}
        for k,v in srj_dict["attributes"].items():
            if len(v) != 0:
                data[k] = v[0]
            else:
                data[k] = ""
        return data
    except KeyError:
        return None

def format_user_info(user_data):
    try:
        info = {
            "cn" : user_data["attributes"]["cn"][0],
            "sn" : user_data["attributes"]["sn"][0],
            "manager_display_name" : "",
            "managerID" : "",
            "businessCategory" : "",
            "telephoneNumber" : "",
            "mail" : user_data["attributes"]["mail"][0],
            "uid" : user_data["attributes"]["uid"][0]
        }
        if len(user_data["attributes"]["telephoneNumber"]) != 0:
            info["telephoneNumber"] = user_data["attributes"]["telephoneNumber"][0]
        if len(user_data["attributes"]["businessCategory"]) != 0:
            info["businessCategory"] = user_data["attributes"]["businessCategory"][0]
        if len(user_data["attributes"]["displayName"]) != 0:
            info["displayName"] = user_data["attributes"]["displayName"][0]
        if len(user_data["attributes"]["manager"]) != 0:
            info["manager"] = user_data["attributes"]["manager"][0]
            info["managerID"] = user_data["attributes"]["manager"][0].split(",")[0].split("=")[1]
            fmdn = getUserAttributes(info["managerID"], ["displayName"])
            if fmdn is not None:
                info["manager_display_name"] = fmdn["displayName"]
            else:
                info["manager_display_name"] = ""
        return info
    except:
        return None
        
def getUsers(size_limit, with_fils):
    if not ldapState:
        return None
    search_dn = config['USER_DN'] +','+ config['BASE_DN']
    if size_limit is None:
        response = ldap.search(
            search_base = search_dn,
            search_filter = '(objectClass=*)',
            attributes = ["uid","cn","sn","displayName","manager","mail","businessCategory","telephoneNumber"],
            dereference_aliases = "ALWAYS"
        )
    else:
        response = ldap.search(
            search_base = search_dn,
            search_filter = '(objectClass=*)',
            attributes = ["uid","cn","sn","displayName","manager","mail","businessCategory","telephoneNumber"],
            dereference_aliases = "ALWAYS",
            size_limit = int(size_limit) + 1
        )
    
    entry = ldap.entries
    all_users = []
    if with_fils == "yes":
        all_user_info = []
    # count = 0
    for user in entry:
        user_data = json.loads(user.entry_to_json())
        info = format_user_info(user_data)
        if info is None:
            continue
        all_users.append(info)
        if with_fils == "yes":
            all_user_info.append(getFils(info))
    #     count+=1
    # print(count)
    if response:
        if with_fils == "yes":
            return all_users, all_user_info
        else:
            return all_users, None
    else:
        return None, None

def getFils(user):
    user_info = {
        "info" : user,
        "fils" : [] #come back
    }
    search_dn = config['USER_DN'] +','+ config['BASE_DN']
    user_dn = getUserDn(user["uid"])
    ldap.search(
        search_base = search_dn,
        search_filter = f'(&(objectClass=person)(manager={user_dn}))',
        attributes = ["uid","cn","sn","displayName","manager","mail","businessCategory","telephoneNumber"],
        dereference_aliases = "ALWAYS"
    )
    entry = ldap.entries
    for user in entry:
        user_data = json.loads(user.entry_to_json())
        info = format_user_info(user_data)
        if info is None:
            continue
        user_info["fils"].append(info)
    return user_info
   
def userChild(user):
    """search_dn = config['USER_DN'] +','+ config['BASE_DN']
    if all_users is None:
        return jsonify({"message":"Bad request", "status": "failed"}),400
    uinfo = get_userInfo(search_dn, uid)
    if uinfo is None:
        return jsonify({"message":"Bad request", "status": "failed"}),400
    data = {
        "cn": uinfo["cn"][0],
        "displayName": uinfo["displayName"][0],
        "sn": uinfo["sn"][0],
        "uid": uinfo["uid"][0],
        "mail": uinfo["mail"][0],
        "telephoneNumber": "",
        "businessCategory": "",
        "managerID":"",
        "manager_display_name":""
    }
    if len(uinfo["telephoneNumber"]) != 0:
        data["telephoneNumber"] = uinfo["telephoneNumber"][0]
    if len(uinfo["businessCategory"]) != 0:
        data["businessCategory"] = uinfo["businessCategory"][0]
    if len(uinfo["manager"]) != 0:
        managerID = uinfo["manager"][0].split(",")[0].split("=")[1]
        data["managerID"] = managerID     
        managerInfo = get_userInfo(search_dn, managerID)
        if managerInfo is None:
            data["manager_display_name"] = ""
        else:
            data["manager_display_name"] = managerInfo["displayName"][0]"""
    userFils = getFils(user)
    return userFils
      
def getUserManager(uid):
    all_user_info = getUsers(None, True)[1]
    for user2 in all_user_info:
        for fils in user2["fils"]:
            if fils["uid"] == uid:
                return user2["info"]   
    return None

def send2FA_code(mail):
    try:
        # generating random PyOTP secret keys
        totp_secret = pyotp.random_base32()
        qr_url = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=mail, issuer_name='Azumaril')
        FA2.insert_one({"totp_secret":totp_secret,"mail":mail,"qr_url":qr_url})
        #-----this is for test purpose
        #-----Display the qr code in the terminal
        comand = "qr "+ qr_url
        print(comand)
        os.system(comand)
        #------------ 
        return {"mail":mail, "otp_secret":totp_secret, "qr_url":qr_url}
    except:
        return None
    
def user_exists(userID):
    entry = ldap.search('uid=' + userID + ',' + config['USER_DN'] +','+ config['BASE_DN']
    , '(objectclass=person)')
    if entry:
        return True
    return False

def getLastUid():
    search_dn = config['USER_DN'] +','+ config['BASE_DN']
    ldap.search(
        search_dn,
        f'(objectclass=*)',
        attributes = ['uid']
    )
    uid_list = []
    for entry in ldap.entries:
        info = ast.literal_eval(entry.entry_to_json())
        try:
            uid_list.append(info["attributes"]["uid"][0])
        except IndexError:
            pass
    return uid_list[-1]

def new_seq(old_seq):
    temp = old_seq
    pos_digit = len(old_seq) - 1
    model = "0000000"

    if old_seq == "":
        return model

    while (pos_digit != 0):
        if chr(ord(old_seq[pos_digit]) + 1) <= "9":
            add = chr(ord(old_seq[pos_digit]) + 1)
            new = temp[:pos_digit] + add + temp[pos_digit+1:]
            return new
        else:
            temp = temp[:pos_digit] + "0" + temp[pos_digit+1:]
            pos_digit -= 1                                                                                                                            
    temp = temp.replace("9", "0")
    if (len(temp) == 7):
        temp = "a" + temp
        old_seq = chr(ord("a") -1) + old_seq
    if chr(ord(old_seq[0]) + 1) <= "z":
        add = chr(ord(old_seq[0]) + 1)
        new = temp[:0] + add + temp[0+1:]
        return new
    return model + "0"

def get_sequence():
    all_seq = db002["uid_seq"]
    old_seq = all_seq.find().sort([('seq', -1)]).limit(1)
    old_seq = list(old_seq)
    if len(list(old_seq)) == 0:
        new = new_seq("")
    else:
        new = new_seq(old_seq[0]["seq"])
    all_seq.insert_one({"seq": new})
    return (new)

def unique_uid():
    return new_seq(getLastUid())

def get_userid_by_token():
    auth_token = request.headers.get('Authorization')
    if auth_token is not None:
        auth_token = auth_token.split()[1]
        tokens = db002["tokens"]
        try:
            userid=tokens.find_one({"token":""+auth_token+""})["user_uid"]
            return userid
        except:
            return "someone"
    else:
        return "someone"
    
def isErrorKey(user, key):
    try:
        user[key]
        return True and user[key] != ""
    except KeyError:
        return False
 
def getUserGroup(user_dn, uid=""):
    search_dn2 = config['GROUP_DN'] +','+ config['BASE_DN']
    ldap.search(search_dn2, f'(|(member={user_dn})(memberUid={uid}))')
    groups = []
    for entry in ldap.entries:
        group = ast.literal_eval(entry.entry_to_json())
        groups.append(group['dn'].split(",")[0].split("=")[1])
    return groups

def verifyTechnicalProfil(elementId):
    elem = technical_profiles.find_one({"technical_profil_id": elementId})
    return True if elem else False

def checkVisibility(visibility):
    all_groups = get_all_groups()
    not_found = []
    found = []
    for i in visibility:
        if i in all_groups:
            found.append(i)
        else:
            not_found.append(i)
    return found, not_found

def checkTechnicalProfil(technical_profil):
    not_found = []
    found = []
    for i in technical_profil:
        if not verifyTechnicalProfil(i):
            not_found.append(i)
        else:
            found.append(i)
    return found, not_found

def getGroupMember(name):
    search_dn = config['GROUP_DN'] + ',' + config['BASE_DN']
    ldap.search(
        search_dn,
        attributes = ['member'],
        search_filter=f'(cn={name})'
    )
    members_dn = []
    for entry in ldap.entries:
        member = ast.literal_eval(entry.entry_to_json())
        members_dn.extend(member["attributes"]["member"])
    members_uid = []
    for mdn in members_dn:
        members_uid.append(mdn.split(",")[0].split("=")[1])
    return members_uid
    
def approval(taskid):
    endPoint = airflow["url"]
    URL = endPoint + "/api/v1/dags/approval_workflow/dagRuns"
    try:
        me = {"username":airflow["value"]["username"], "password":airflow["value"]["password"]}
        data = "{\"conf\": {\"task_id\":\""+taskid+"\"}, \"dag_run_id\": \""+"airflow_"+taskid + str(random.random()) +"\" }"
        headers = {'Content-Type': 'application/json', 'accept': 'application/json' }
        results = requests.post(URL, data, auth=(me["username"], me["password"]), headers=headers)
        if results.status_code == 200:
            return "ok", 200
        else: return "something went wrong", results.status_code
    except Exception as err:
        return str(err)
    
def confirm_approval_role(taskid, answer):
    endPoint = airflow["url"]
    URL = endPoint + "/api/v1/dags/confirm_approval_role/dagRuns"
    try:
        me = {"username":airflow["value"]["username"], "password":airflow["value"]["password"]}
        randomm = str(random.random())
        mapa = {
            "conf" : {
                "task_id" : taskid,
                "answer" : answer
            },
            "dag_run_id" : "airflow_" + taskid + randomm
        }
        data = json.dumps(mapa,default=str)
        headers = {'Content-Type': 'application/json', 'accept': 'application/json' }
        results = requests.post(URL, data, auth=(me["username"], me["password"]), headers=headers)
        print("here")
        print(results.status_code)
        print("here")
        if results.status_code == 200:
            return "ok", 200
        else: return "something went wrong", results.status_code
    except Exception as err:
        return str(err)

def removeAll(the_list, val):
    try:
        while True:
            the_list.remove(val)
    except ValueError:
        pass
    return the_list

def requestThread(req, userid):
    try:
        manager = getUserManager(userid)
        approvers = {
            "manager" : "",
            "manager_manager" : "",
            "others" : []
        }
        others = []
        userGroups = getUserGroup(getUserDn(userid), uid = userid)
        for ug in userGroups:
            ugMembers = getGroupMember(f"{ug}_approvers")
            others.extend(ugMembers)
        if manager is not None:
            managerID = manager["uid"]
            approvers["manager"] = managerID
            if managerID in others:
                others = removeAll(others, managerID)
            manager_manager = getUserManager(managerID)
            if manager_manager is not None:
                manager_managerID = manager_manager["uid"]
                approvers["manager_manager"] = manager_managerID
                if manager_managerID in others:
                    others = removeAll(others, manager_managerID)
        mylist = list(dict.fromkeys(others))
        approvers["others"].extend(mylist)
        task_id = str(ObjectId())
        role_requested = []
        business_role_ids = req["business_role_ids"]
        for bri in business_role_ids:
            profile_role = profile_roles.find_one({"profil_role_id" : bri})
            tps = []
            for itp in profile_role["id_technical_profil"]:
                itpInfo = technical_profiles.find_one({"technical_profil_id" : itp})
                name = ""
                crtct_lvl = ""
                app_type_id = ""
                if itpInfo is not None:
                    name = itpInfo["name"]
                    crtct_lvl = itpInfo["criticity_level"]
                    app_type_id = itpInfo["app_type_id"]
                validation_state = "pending"
                if int(crtct_lvl) > 1:
                    validation_state = ["pending", "pending"]
                
                tps.append(
                    {
                        "id" : itp,
                        "name" : name,
                        "app_type_id" : app_type_id,
                        "criticity_level" : crtct_lvl,
                        "state" : "pending",
                        "validation_state" : validation_state
                    }
                )
            role_requested.append(
                {
                    "state" : "pending",
                    "validation_state" : "pending",
                    "profil_role_id" : profile_role["profil_role_id"],
                    "name" : profile_role["name"],
                    "criticity_level" : profile_role["criticity_level"],
                    "technical_profiles_state" : tps
                }
            )
        token = encode_token(
            token_type="task_token",
            user_uid = userid,
            data = {"task_id" : task_id}, 
            exp_days = profile_role_exp
        )["token"]
        now = datetime.now()
        exp = now + timedelta(hours=profile_role_exp)
        tasks.insert_one(
            {
                "type" : "profile_role_request",
                "applicant": userid,
                "status": "pending",
                "creation_date": now,
                "expiration_date": exp,
                "number_of_attempts": 0,
                "type_of_request": req["type_of_request"],
                "task_id": task_id,
                "role_requested": role_requested,
                "logs": "",
                "approvers": approvers,
                "token" : token
            }
        )
        print("--------------go--------------")
        approval(task_id)
        print("--------------go--------------")
    except:
        print(traceback.format_exc())

@ORGANIGRAM_REQUEST.route('/roles', methods=['GET'])
def getGroups():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    data = get_all_groups()
    if data is None:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400
    else:
        return jsonify({"data":data,"message":"", "status": "success"})

@ORGANIGRAM_REQUEST.route('/role/create', methods=['POST'])
def createGroup():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    name = req["name"]
    if name in get_all_groups():
        return jsonify({
            "status": "failed",
            "message": f"The role {name} already exist"
        }), 409
    groupDN = f'cn={name},'+ config['GROUP_DN'] + "," + config['BASE_DN']
    approversGroupDN = f'cn={name}_approvers,'+ config['GROUP_DN'] + "," + config['BASE_DN']
    objectClass = ['groupOfNames', 'top']
    first_member_uid = get_userid_by_token()
    first_member_dn = getUserDn(get_userid_by_token())
    first_member_roles = getUserGroup(first_member_dn, first_member_uid)
    AUTHORIZED = "admin" in first_member_roles or "rh" in first_member_roles
    if not AUTHORIZED:
        return jsonify({
            "status": "failed",
            "message": f"Insufficient access rights, you have not role admin or rh"
        }), 401
    attr = {
        'cn': name,
        'member': first_member_dn
    }
    
    attr2 = {
        'cn': f'{name}_approvers,',
        'member': first_member_dn
    }
    try:
        result = ldap.add(
                dn = groupDN,
                object_class = objectClass,
                attributes = attr
            )
        result2 = ldap.add(
                dn = approversGroupDN,
                object_class = objectClass,
                attributes = attr2
            )
    except:
        print(traceback.format_exc())
    if result and result2:
        return jsonify({
            "status": "success",
            "message": f"Role {name} successfully added"
        })
    else:
        return jsonify({
            "status": "failed",
            "message": "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/role/delete', methods=['DELETE'])
def deleteGroup():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    name = req["name"]
    if name not in get_all_groups():
        return jsonify({
            "status": "failed",
            "message": f"The role {name} already deleted or is not existing"
        }), 400
    groupDN = getGroupDn(name)
    this_user_uid = get_userid_by_token()
    this_user_dn = getUserDn(get_userid_by_token())
    this_user_roles = getUserGroup(this_user_dn, this_user_uid)
    AUTHORIZED = "admin" in this_user_roles or "rh" in this_user_roles
    if not AUTHORIZED:
        return jsonify({
            "status": "failed",
            "message": f"Insufficient access rights, you have not role admin or rh to delete this role"
        }), 401
    result = ldap.delete(groupDN)
    if result:
        return jsonify({
            "status": "success",
            "message": f"Role {name} successfully deleted"
        })
    else:
        return jsonify({
            "status": "failed",
            "message": "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/register', methods=['POST'])
def RegisterLdap():
    user = get_data()
    if user is None:
        return jsonify({"message":"Missing params", "status": "failed"}), 400
    # response = ldap_manager.authenticate(user["uid"], user["password"])
    #userID = (user['firstname'][0]+user['lastname']).lower()
    userID = unique_uid()
    user_dn = 'uid=' + userID + ',' + config['USER_DN'] +','+ config['BASE_DN']
    if not isErrorKey(user, "firstname") and not isErrorKey(user, "lastname"):
        return jsonify({"message":"firstname and lastname is required", "status": "failed"}),400
    
    if not isErrorKey(user, "email") and not isErrorKey(user, "password"):
        return jsonify({"message":"email and password is required", "status": "failed"}),400
    
    if not isErrorKey(user, "email") and not isErrorKey(user, "password"):
        return jsonify({"message":"email and password is required", "status": "failed"}),400
    passwordTest = policy(user["password"])
    if not passwordTest[0]:
        # invalidity_found = passwordTest[1]
        return jsonify(
            {
                "error":"The password must be at least 8 chars long, \
                            contain capital letter, a number and a special character"
            }
        ), 400
    if not validMail(user["email"]):
            return jsonify({"status":"failed", "message":"Bad email"}), 400
    fuser = users.find_one({"email" : user["email"]})
    if fuser is not None:
        return jsonify({
            "status" : "failed",
            "message" : "User with this email already exist"
        }), 409
    if not isErrorKey(user, "role"):
        return jsonify({"message":"role is required", "status": "failed"}),400
    
    fullname = user['firstname'] + ' ' + user['lastname']
    homeDirectory = "/home/"+user['firstname'][0]+user['lastname']
    hasManager = isErrorKey(user, 'managerID')
    hasBusinessCategory = isErrorKey(user, 'businessCategory')
    hasTel = isErrorKey(user, 'tel')
    is2fa = isErrorKey(user, '2fa')
    fa2 = "no"
    if is2fa:
        if user["2fa"] != "yes" and user["2fa"] != "no":
            return jsonify({"message": f"2fa must be yes or no but {fa2} was provided", "status": "failed"}), 400 
        else:
            fa2 = user["2fa"]
    try:
        #define all attributes
        attributes = {
            'cn' : user['firstname'],
            # 'givenName' : 'Beatrix',
            'sn' : user['lastname'],
            # 'departmentNumber' : 'DEV',
            'userPassword' : user['password'],
            'HomeDirectory' : homeDirectory,
            'gidNumber' : 10002,
            'uidNumber' : 10002,
            'shadowWarning' : 7,
            'shadowMin' : 1,
            'shadowMax' : 60,
            'shadowInactive' : 60,
            'loginShell' : '/bin/bash',
            'employeeNumber' : userID,
            'displayName' : fullname,
            'mail' : user["email"]
        }
        if hasManager:
            managerID = 'uid=' + user['managerID'] + ',' + config['USER_DN'] +','+ config['BASE_DN']
            attributes['manager'] =  managerID
        if hasBusinessCategory:
            attributes['businessCategory'] =  user['businessCategory']
        if hasTel:
            attributes['telephoneNumber'] = user["tel"]
            
        object_class = ['inetOrgPerson','posixAccount','shadowAccount','person']
        
        #check if role existing
        search_dn = config['GROUP_DN'] +','+ config['BASE_DN']  
        cn = user["role"]
        tr = ldap.search(
            search_dn,
            f'(&(objectclass=*)(cn={cn}))',
            attributes=['cn']
        )
        if not tr:
            return jsonify({"message": f"The role of the user isn't defined", "status": "failed"}), 400
        
        #add user
        result = ldap.add(
            dn = user_dn,
            object_class = object_class,
            attributes = attributes
        )
        if result:
            FA2info.insert_one({"uid":userID, "2fa":fa2, "mail":user["email"]})
            users.insert_one(
                {
                    "uid" : userID,
                    "email" : user["email"],
                    "firstname" : user["firstname"],
                    "lastname" : user["lastname"],
                    "business_roles" : [],
                    "is_activated" : True,
                    "log_mode" : {
                        "success":True,
                        "warning":False,
                        "debug":False,
                        "error":False
                    }
                }
            )
            if is2fa:
                if user["2fa"] == "yes":
                    send2FA_code(user["email"])
            addUsersInGroups(ldap, user_dn, readonly_group)
            addUsersInGroups(ldap, user_dn, getGroupDn(user["role"]))
            token = encode_auth_token(userID)["token"]
            groups = getUserGroup(user_dn, userID)
            user_info = {}
            for k, v in get_userInfo(user_dn, userID).items() :
                try :
                    user_info[k] = v[0]
                except :
                    user_info[k] = ""
            return json.dumps(
                {
                    "status" : "success",
                    "message" : "Account " + fullname + " created successfully",
                    "token" : token,
                    "data" : user_info,
                    "user_groups":groups
                },
                indent = 2
            )
        else:
            return jsonify({"message": "Something went wrong", "status": "failed"}),400
        
    except LDAPException as e:
        response = e
        return response

@ORGANIGRAM_REQUEST.route('/user/hierarchy', methods=['GET'])
def getLdapUsersIrh(size):
    """
        Return all secrets
        @params : workspaceid,user_dn and password 
    """
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    size = None
    args = request.args
    data_dict = args.to_dict()
    if isErrorKey(data_dict, "size"):
        size = data_dict["size"]
    data = getUsers(size, True)
    all_users = data[0]
    all_user_info = data[1]
    for us in all_user_info:
        us["fils"] = []
    if all_users is not None:
        sorted_data = []
        for obj in all_user_info:
            if obj['info']['managerID'] == '':
                sorted_data.append(obj)
        
        for obj2 in sorted_data:
            fetchSons(obj2, all_user_info)
            
        return json.dumps({"data":sorted_data, "status": "success"}, indent=2),200
    else:
        return jsonify({"message":"Bad request", "status": "failed"}),400

@ORGANIGRAM_REQUEST.route('/user/all', methods=['GET'])
def getLdapUsers():
    """
        Return all secrets
        @params : workspaceid,user_dn and password 
    """
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    size = None
    with_fils = False
    args = request.args
    data = args.to_dict()
    if isErrorKey(data, "size"):
        size = data["size"]
    if isErrorKey(data, "with_fils"):
        with_fils = data["with_fils"]
    data = getUsers(size, with_fils)
    all_users = data[0]
    data_to_display = all_users
    if with_fils == "yes":
        data_to_display = data[1]
    if all_users is not None:  
        default_str = json.dumps({"status": "success", "data":data_to_display}, indent=2)
        return json.loads(default_str)
    else:
        return jsonify({"message":"Bad request", "status": "failed"}),400

@ORGANIGRAM_REQUEST.route('/user/info', methods=['GET'])
def userInfoRoute():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        uid = get_userid_by_token()
        search_dn = config['USER_DN'] +','+ config['BASE_DN']
        uinfo = get_userInfo(search_dn, uid)
        user_info = {}
        for k, v in uinfo.items() :
            try :
                user_info[k] = v[0]
            except :
                user_info[k] = ""
        return jsonify({
            "status" : "success",
            "message" : "Successfully fetched user information",
            "data" : user_info
        })
    except:
        return jsonify({
            "status" : "failed",
            "message" : "Something whent wrong"
        }), 400
    
@ORGANIGRAM_REQUEST.route('/user/childs', methods=['POST'])
def getUserChild():  
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        user = getUserAttributes(req["uid"], ["cn", "sn", "businessCategory", "telephoneNumber", "mail", "uid"])
        uChild = userChild(user)
        uChild["status"] = "success"
        return jsonify(uChild)
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@ORGANIGRAM_REQUEST.route('/user/update', methods=['POST'])
def updateUser():
    validated = validation()
    if not validated[0]:
        return validated[1]
    user = validated[1]
    search_dn = config['USER_DN'] +','+ config['BASE_DN']
    if not isErrorKey(user, "uid"):
        return jsonify({"message":"uid is required", "status": "failed"}), 400
    uid = user["uid"]
    default = get_userInfo(search_dn, uid)
    try:
        updateAttributes(default, user)
        return jsonify({"status":"success"})
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@ORGANIGRAM_REQUEST.route("/user/change/password",  methods=['POST'])
def change_password():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    user_dn = getUserDn(req["uid"])
    hashed_password = hashed(HASHED_SALTED_SHA, req["newPassword"])
    isCorrectOldPassword = Connection(
        server,
        user = user_dn,
        password = req["oldPassword"]
    )
    if(isCorrectOldPassword.bind()):
        taskid = str(ObjectId())
        tasks.insert_one({
            "taskid" : taskid,
            "type" : "ldap_change",
            "user_dn" : user_dn, 
            "user_password" : req["oldPassword"],
            "newPassword" : hashed_password,
            "admin_dn":"null",
            "admin_password":"null",
            "admin_mod" : "no",
            "status":"pending"
        })
        run_dag(taskid)
        return jsonify({"status":"success","message":"change password request is now processing.."}),200
    else:
        return jsonify({"message":"Unable to change password, old password is incorect or bad user uid", "status": "failed"}) ,400

@ORGANIGRAM_REQUEST.route("/admin/change/password",  methods=['POST'])
def admin_change_password():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    user_dn = getUserDn(req["user_uid"])
    admin_dn = getUserDn(req["admin_uid"])
    admin_password = req["admin_password"]
    hashed_password = hashed(HASHED_SALTED_SHA, req["newPassword"])
    isCorrectOldPassword = Connection(
        server,
        user = admin_dn,
        password = admin_password
    )
    if(isCorrectOldPassword.bind()):
        taskid = str(ObjectId())
        tasks.insert_one({
            "taskid" : taskid,
            "type" : "ldap_change",
            "user_dn" : user_dn,
            "newPassword" : hashed_password,
            "admin_dn": admin_dn,
            "admin_password":admin_password,
            "admin_mod" : "yes",
            "status":"pending"
        })
        run_dag(taskid)
        return jsonify({"status":"success","message":"change password request is now processing.."}),200
    else:
        return jsonify({"message":"Unable to change password, bad admin credentials", "status": "failed"}) ,400

@ORGANIGRAM_REQUEST.route('/user/add/manager', methods=['POST'])
def addManager():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        result = ldap.modify(getUserDn(req["uid"]), {
            'manager': [(MODIFY_ADD, [getUserDn(req["managerID"])])]
        })
        if result:
            return jsonify({"status":"success"}),200
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@ORGANIGRAM_REQUEST.route('/user/rights/request', methods=['POST'])
def requestRights():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    if isErrorKey(req, 'user_uid'):
        uid = req["user_uid"]
    else:
        return jsonify({"message": "user_uid is required", "status": "failed"}), 400
    try:
        
        taskid = str(ObjectId())
        objet = "Demande de permissions"
        if not isErrorKey(req, 'group_name'):
            return jsonify({"message": "group_name is required", "status": "failed"}), 400 
        group_name = req["group_name"]
        
        #check if role existing
        search_dn = config['GROUP_DN'] +','+ config['BASE_DN']  
        tr = ldap.search(
            search_dn,
            f'(&(objectclass=*)(cn={group_name}))',
            attributes=['cn']
        )
        if not tr:
            return jsonify({"message": f"The role {group_name} isn't defined", "status": "failed"}), 400
        
        #check if user has already this role
        if group_name in getUserGroup(getUserDn(uid), uid):
            return jsonify({"message": f"user {uid} has already the role {group_name}", "status": "failed"}), 400

        user_uid = req["user_uid"]
        message = f"Autoriser {user_uid} à acceder à {group_name}? \n \
            Accéder à ce lien pour accepter servername/user/rights/grant/{taskid}"
        manager = getUserManager(uid)# ANCHOR
        if manager is None:
            return jsonify({"message":"This user has no manager", "status": "failed"}), 400
        if group_name in getUserGroup(getUserDn(manager["uid"]), manager["uid"]):
            tasks.insert_one({"taskid":taskid,"type":"rights_request","user_uid":req["user_uid"],"group_name":req["group_name"]})
            Thread(target = mail_sender, args=(manager["mail"], objet, message,)).start()
            return jsonify({"status":"success", "message":f"rights request for user {uid} is now processing..email sent to manager"}),200
        else:
            tasks.insert_one({"taskid":taskid,"type":"rights_request","user_uid":req["user_uid"],"group_name":req["group_name"]})
            Thread(target = mail_sender, args=(manager["mail"], objet, message,)).start()
            return jsonify({"message":"Your manager has not this role but will ask for you. request is being processed", "status": "success"})
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@ORGANIGRAM_REQUEST.route('/user/rights/grant_deny/<string:taskid>', methods=['POST'])
def grantRights(taskid):
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        taskInfo = tasks.find_one({"taskid" : taskid})
        uid = taskInfo["user_uid"]
        search_dn = config['USER_DN'] +','+ config['BASE_DN']
        user_mail = get_userInfo(search_dn, uid)["mail"][0]
        action = req["action"]
        if action != "grant" and action != "deny":
            return jsonify({"message":"actions allowed are grant or deny but {action} were provided", "status": "failed"}), 400
        if action == "grant":
            result = addUsersInGroups(ldap, getUserDn(uid), getGroupDn(taskInfo["group_name"]))
            if not result:
                return jsonify({"message":"Bad user dn or bad group dn", "status": "failed"}), 400
            if taskInfo["group_name"] == "admin":
                result = ldap.modify(getGroupDn(taskInfo["group_name"]), {
                    'memberUid': [(MODIFY_ADD, [uid])]
                })
            message = "Rights request granted by your manager"
            Thread(target = mail_sender, args=(user_mail, "Rights request", message,)).start()
            return jsonify({"status":"success", "message":f"rights request granted for user {uid}"})
        if action == "deny":
            message = "Rights request denied by your manager"
            Thread(target = mail_sender, args=(user_mail, "Rights request", message,)).start()
            return jsonify({"status":"success", "message":f"rights request denied for user {uid}"})
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@ORGANIGRAM_REQUEST.route('/application/all', methods=['GET'])
def allApp():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
    try:
        apps = applications.find({}, {"_id" : 0})
        data = []
        for ap in apps:
            data.append(ap)
        return json.dumps(
            {
                "status" : "success",
                "message" : "",
                "data" : data
            },
            indent = 2,
            default = str
        )
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/application/create', methods=['POST'])
def createApp():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        user_uid = get_userid_by_token()
        user_dn = getUserDn(get_userid_by_token())
        first_member_roles = getUserGroup(user_dn, user_uid)
        AUTHORIZED = "admin" in first_member_roles
        if not AUTHORIZED:
            return jsonify({
                "status": "failed",
                "message": f"Insufficient access rights, you has not role admin"
            }), 401
        appid = str(ObjectId())
        name = req["name"]
        app_type = req["type"]
        appInfo = {
            "app_id" : appid,
            "name" : name,
            "type" : app_type,
            "app_creds" : req["app_creds"]
        }
        applications.insert_one(appInfo)
        return json.dumps(
            {
                "status" : "success",
                "message" : f"Application {name} successfully created",
                "data" : appInfo
            },
            indent = 2,
            default = str
        )
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/application/update', methods=['POST'])
def updateApp():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        user_uid = get_userid_by_token()
        user_dn = getUserDn(get_userid_by_token())
        first_member_roles = getUserGroup(user_dn, user_uid)
        AUTHORIZED = "admin" in first_member_roles
        if not AUTHORIZED:
            return jsonify({
                "status": "failed",
                "message": f"Insufficient access rights, you has not role admin"
            }), 401
        appInfo = {}
        if not isErrorKey(req, "app_id"):
            return jsonify({
                "status": "failed",
                "message": "app_id is required"
            }), 400
        if isErrorKey(req, "name"):
            name = req["name"]
            appInfo["name"] = name
            appInfo["type"] = name
        if isErrorKey(req, "app_creds"):
            appInfo["app_creds"] = req["app_creds"]
        applications.find_one_and_update(
            {'app_id': req["app_id"]},
            {
                "$set": appInfo
            },
            upsert=True
        )
        return json.dumps(
            {
                "status" : "success",
                "message" : f"Application {name} successfully updated"
            },
            indent = 2,
            default = str
        )
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/profil/role/all', methods=['GET'])
def getRoles():
    validate = tokenValidation()
    if validate["status"]:
        try:
            userid = get_userid_by_token()
            user_groups = getUserGroup(getUserDn(userid), uid=userid)
            allowed_viewer = [config["ROLE_MGR"], config["ROLE_VIEWER"]]
            check1 = any(item in user_groups for item in allowed_viewer)
            if not check1:
                return jsonify({
                    "status" : "failed",
                    "message" : "Not allowed to view profil role"
                }), 401
            data = []
            allRoles = profile_roles.find()
            for doc in allRoles:
                check2 = any(item in user_groups for item in doc["visibility"])
                if check2:
                    data.append({
                        "profil_role_id":doc["profil_role_id"], 
                        "name": doc["name"],
                        "id_technical_profil": doc["id_technical_profil"],
                        "visibility": doc["visibility"]
                    })
            return jsonify({"status":"success","data":data})
        except Exception:
            return jsonify({"status":"failed", "message":"Something went wrong"}),400
    else:
        return jsonify({"message":validate["message"], "status": "failed"}),401

@ORGANIGRAM_REQUEST.route('/profil/role/create', methods=['POST'])
def createRole():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["ROLE_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to create profil role"
            }), 401
            
        if not isErrorKey(req, "app_type_id"):
            return jsonify({
                "status" : "failed",
                "message" : "app_type_id is required"
            }), 401
        if not isErrorKey(req, "name"):
            return jsonify({
                "status" : "failed",
                "message" : "name is required"
            }), 401
        check = profile_roles.find_one({"name" : req["name"]})
        if check:
            return jsonify({"status":"failed", "message":"This profile role already exists."}),400
        if applications.find_one({"app_id":req["app_type_id"]}) is None:
            appid = req["app_type_id"]
            return jsonify({
                "status" : "failed",
                "status" : f"Application with id {appid} not found in the organigram apps",
            }), 404
        if not isErrorKey(req, "visibility"):
            return jsonify({
                "status" : "failed",
                "message" : "visibility is required"
            }), 400
        if len(req["visibility"]) == 0:
            return jsonify({
                "status" : "failed",
                "message" : "visibility is required"
            }), 400
        if req["criticity_level"] > 2 or req["criticity_level"] < 0:
            return jsonify({
                "status" : "failed",
                "message" : "criticity_level must be between 0 and 2"
            }), 400
            
        visibility = req["visibility"]
        tpInfo = checkTechnicalProfil(req["id_technical_profil"])
        visibilityInfo = checkVisibility(visibility)
        if len(visibilityInfo[0]) == 0:
            return jsonify({
                "status" : "failed",
                "message" : "The visibility group list is not correct"
            }), 400
        profil_role_id = str(ObjectId())
        newRole = {
            "profil_role_id": profil_role_id,
            "name": req["name"],
            "app_type_id": req["app_type_id"],
            "id_technical_profil": tpInfo[0],
            "visibility": visibilityInfo[0],
            "criticity_level": req["criticity_level"]
        }
        profile_roles.insert_one(newRole)
        return json.dumps(
            {
                "status":"success",
                "message":"Role create successfully",
                "data": newRole,
                "not_found_technical_profil": tpInfo[1],
                "not_found_visibility": visibilityInfo[1]
            },
            indent=2,
            default=str
        )
    except Exception:
        return jsonify({"status":"failed", "message":"Something went wrong"})

@ORGANIGRAM_REQUEST.route('/profil/role/update', methods=['PUT'])
def updateRole():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["ROLE_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to update profil role"
            }), 401
        if not isErrorKey(req, "profil_role_id"):
            return jsonify({"message":"Must provide id fields", "status": "failed"}), 400
        
        profil_role = profile_roles.find_one({"profil_role_id": req["profil_role_id"]})
        
        if not profil_role:
            return jsonify({"status": "failed", "message":"role does not exist"}), 400
        dataToUpdate = {}
        
        if isErrorKey(req, "name"):
            for pr in profile_roles.find({},{"name":1, "profil_role_id":1}):
                if pr["name"] == req["name"] and pr["profil_role_id"] != req["profil_role_id"]:
                    return jsonify({
                            "status" : "failed",
                            "message" : f"profile role with name {req['name']} already exist, please provide another name"
                        }), 409
            dataToUpdate["name"] = req["name"]
            
        if isErrorKey(req, "app_type_id"):
            if applications.find_one({"app_id" : req["app_type_id"]}) is None:
                return jsonify({
                    "status" : "failed",
                    "message" : f"application with app_id {req['app_type_id']} not found, please provide another app_type_id"
                }), 404
            dataToUpdate["app_type_id"] = req["app_type_id"]
            
        if isErrorKey(req, "criticity_level"):
            if int(req["criticity_level"])>2 or int(req["criticity_level"])<0:
                return jsonify({
                    "status" : "failed",
                    "message" : "criticity_level must be 0,1 or 2"
                }), 400
            dataToUpdate["criticity_level"] = req["criticity_level"]
        # all_groups = get_all_groups()
        # visibility = profil_role["visibility"]
        # not_found_visibility = []
        if isErrorKey(req, "visibility"):
            dataToUpdate["visibility"] = req["visibility"]
        # if isErrorKey(req, "visibility_to_add"):
        #     toAdd = req["visibility_to_add"]
        #     for i in toAdd:
        #         not_already_in = not (i in visibility)
        #         in_groups = i in all_groups
        #         if not_already_in and in_groups:
        #             visibility.append(i)
        #         if not in_groups:
        #             not_found_visibility.append(i)
        #     dataToUpdate["visibility"] = visibility
                    
        # if isErrorKey(req, "visibility_to_remove"):
        #     toRemove = req["visibility_to_remove"]
        #     for i in toRemove:
        #         already_in = i in visibility
        #         if already_in:
        #             visibility.remove(i)
        #     dataToUpdate["visibility"] = visibility
        
        # not_found_technical_profil = []
        # found_technical_profil = profil_role["id_technical_profil"]
        if isErrorKey(req, "id_technical_profil"):
            dataToUpdate["id_technical_profil"] = req["id_technical_profil"]
        # if isErrorKey(req, "id_technical_profil_to_add"):
        #     toAdd = req["id_technical_profil_to_add"]
        #     for i in toAdd:
        #         not_already_in = not (i in found_technical_profil)
        #         in_db = verifyTechnicalProfil(i)
        #         if not_already_in and in_db:
        #             found_technical_profil.append(i)
        #         if not in_db:
        #             not_found_technical_profil.append(i)
        #     dataToUpdate["id_technical_profil"] = found_technical_profil                   

        # if isErrorKey(req, "id_technical_profil_to_remove"):
        #     toRemove = req["id_technical_profil_to_remove"]
        #     for i in toRemove:
        #         already_in = i in found_technical_profil
        #         if already_in:
        #             found_technical_profil.remove(i)
        #     dataToUpdate["id_technical_profil"] = found_technical_profil  

        profile_roles.find_one_and_update(
            {'profil_role_id': req["profil_role_id"] },
            {
                "$set": dataToUpdate
            },
            upsert=True
        )
        profil_role = profile_roles.find_one({"profil_role_id": req["profil_role_id"]})
        return json.dumps(
            {
                "status" : "success",
                "message" : "Role update successfully",
                # "not_found_visibility" : not_found_visibility,
                # "not_found_technical_profil" : not_found_technical_profil,
                "data" : profil_role
            },
            indent=2,
            default=str
        )
    except Exception:
        return jsonify({"status":"failed", "message":"Something went wrong"}),400

@ORGANIGRAM_REQUEST.route('/profil/role/delete', methods=['DELETE'])
def deleteRole():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["ROLE_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to delete profil role"
            }), 401
        toDelete = profile_roles.find_one({"profil_role_id": req["profil_role_id"]})
        if not toDelete:
            return jsonify({"status": "failed", "message":"Profil role does not exist"}), 400
        profile_roles.delete_one({"profil_role_id": req["profil_role_id"]})
        return jsonify({"status":"success", "message":"Profil role successfully deleted"}),200
    except Exception:
        return jsonify({"status":"failed", "message":"Something went wrong"}),400

@ORGANIGRAM_REQUEST.route('/profil/technical/all', methods=['GET'])
def technicalProfile():
    validate = tokenValidation()
    if validate["status"]:
        try:
            userid = get_userid_by_token()
            user_groups = getUserGroup(getUserDn(userid), uid=userid)
            allowed_viewer = [config["TECHNICAL_MGR"], config["TECHNICAL_VIEWER"]]
            check1 = any(item in user_groups for item in allowed_viewer)
            if not check1:
                return jsonify({
                    "status" : "failed",
                    "message" : "Not allowed to view technical profil"
                }), 401
            data = []
            TechnicalP = technical_profiles.find()
            for doc in TechnicalP:
                check2 = any(item in user_groups for item in doc["visibility"])
                if check2:
                    data.append({
                        "technical_profil_id":doc["technical_profil_id"], 
                        "name": doc["name"],
                        "visibility": doc["visibility"]
                    })
            return jsonify({"status":"success","data":data})
        except Exception:
            return jsonify({"status":"failed", "message":"Something went wrong"}),400
    else:
        return jsonify({"message":validate["message"], "status": "failed"}),401

@ORGANIGRAM_REQUEST.route('/profil/technical/create', methods=['POST'])
def createTechnicalProfile():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["TECHNICAL_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to create technical profil"
            }), 401
        if not isErrorKey(req, "visibility"):
            return jsonify({
                "status" : "failed",
                "message" : "visibility is required"
            }), 400
        if len(req["visibility"]) == 0:
            return jsonify({
                "status" : "failed",
                "message" : "visibility is null"
            }), 400
        if req["criticity_level"] > 2 or req["criticity_level"] < 0:
            return jsonify({
                "status" : "failed",
                "message" : "criticity_level must be between 0 and 2"
            }), 400
        if not isErrorKey(req, "app_type_id"):
            return jsonify({
                "status" : "failed",
                "message" : "app_type_id is required"
            }), 401
        if applications.find_one({"app_id":req["app_type_id"]}) is None:
            appid = req["app_type_id"]
            return jsonify({
                "status" : "failed",
                "status" : f"Application with id {appid} not found in the organigram apps",
            }), 404
        check = technical_profiles.find_one({"name" : req["name"]})
        if check:
            return jsonify({"status":"failed", "message":"This technical_profile already exists."}),400
        TPiD = str(ObjectId())
        visibilityInfo = checkVisibility(req["visibility"])
        if len(visibilityInfo[0]) == 0:
            return jsonify({
                "status" : "failed",
                "message" : "The visibility group list is not correct"
            }), 400
        NewTP = {
            "technical_profil_id": TPiD,
            "name": req["name"],
            "app_type_id": req["app_type_id"],
            "visibility": visibilityInfo[0],
            "criticity_level": req["criticity_level"]
        }
        technical_profiles.insert_one(NewTP)
        return json.dumps(
            {
                "status":"success",
                "message":"technical_profile create successfully",
                "not_found_visibility" : visibilityInfo[1],
                "data":NewTP
            },
            indent=2,
            default=str
        )
    except Exception:
        return jsonify({"status":"failed", "message":"Something went wrong"}),400

@ORGANIGRAM_REQUEST.route('/profil/technical/update', methods=['PUT'])
def updateTechnicalProfile():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["TECHNICAL_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to update technical profil"
            }), 401
            
        if not isErrorKey(req, "technical_profil_id"):
            return jsonify({"message":"technical_profil_id is required", "status": "failed"}), 400
        technical_profil = technical_profiles.find_one({"technical_profil_id": req["technical_profil_id"]})
        if not technical_profil:
            return jsonify({"status": "failed", "message":"technical_profil does not exist"}), 404
        
        dataToUpdate = {}
        if isErrorKey(req, "name"):
            for tp in technical_profiles.find({},{"name":1, "technical_profil_id":1}):
                if tp["name"] == req["name"] and tp["technical_profil_id"] != req["technical_profil_id"]:
                    return jsonify({
                        "status" : "failed",
                        "message" : f"profile role with name {req['name']} already exist, please provide another name"
                    }), 409
            dataToUpdate["name"] = req["name"]
            
        if isErrorKey(req, "app_type_id"):
            if applications.find_one({"app_id" : req["app_type_id"]}) is None:
                return jsonify({
                    "status" : "failed",
                    "message" : f"application with app_id {req['app_type_id']} not found, please provide another app_type_id"
                }), 404
            dataToUpdate["app_type_id"] = req["app_type_id"] 
        if isErrorKey(req, "criticity_level"):
            if int(req["criticity_level"])>2 or int(req["criticity_level"])<0:
                return jsonify({
                    "status" : "failed",
                    "message" : "criticity_level must be 0,1 or 2"
                }), 400
            dataToUpdate["criticity_level"] = req["criticity_level"]
        # all_groups = get_all_groups()
        # visibility = technical_profil["visibility"]
        # not_found_visibility = []
        if isErrorKey(req, "visibility"):
            dataToUpdate["visibility"] = req["visibility"]
        # if isErrorKey(req, "visibility_to_add"):
        #     toAdd = req["visibility_to_add"]
        #     for i in toAdd:
        #         not_already_in = not (i in visibility)
        #         in_groups = i in all_groups
        #         if not_already_in and in_groups:
        #             visibility.append(i)
        #         if not in_groups:
        #             not_found_visibility.append(i)
        #     dataToUpdate["visibility"] = visibility
                    
        # if isErrorKey(req, "visibility_to_remove"):
        #     toRemove = req["visibility_to_remove"]
        #     for i in toRemove:
        #         already_in = i in visibility
        #         if already_in:
        #             visibility.remove(i)
        #     dataToUpdate["visibility"] = visibility
            
        technical_profiles.find_one_and_update(
            {'technical_profil_id': req["technical_profil_id"] },
            {"$set": dataToUpdate},
            upsert=True
        )
        technical_profil = technical_profiles.find_one({"technical_profil_id": req["technical_profil_id"]})
        return json.dumps(
            {
                "status" : "success",
                "message" : "Technical Profile update successfully",
                "data" : technical_profil
            },
            indent=2,
            default=str
        )
    except Exception:
        return jsonify({"status":"failed", "message":"Something went wrong"}),400

@ORGANIGRAM_REQUEST.route('/profil/technical/delete', methods=['DELETE'])
def deleteTechnicalProfile():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["TECHNICAL_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to update technical profil"
            }), 401
        toUpdate = technical_profiles.find_one({"technical_profil_id": req["technical_profil_id"]})
        if not toUpdate:
            return jsonify({"status": "failed", "message":"technical_profil does not exist"}), 400
        technical_profiles.delete_one({"technical_profil_id": req["technical_profil_id"]})
        return jsonify({"status":"success", "message":"Technical profile successfully deleted"})
    except Exception:
        return jsonify({"status":"failed", "message":"Something went wrong"}),400

@ORGANIGRAM_REQUEST.route('/profil/role/request', methods=['POST'])
def profileRoleRequest():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        if not isErrorKey(req, "business_role_ids"):
            return jsonify({
                "status" : "failed",
                "message" : "business_role_ids is required"
            }), 400
        if not isErrorKey(req, "type_of_request"):
            return jsonify({
                "status" : "failed",
                "message" : "type_of_request is required"
            }), 400
        if req["type_of_request"] != "ask" and req["type_of_request"] != "remove":
            return jsonify({
                "status" : "failed",
                "message" : f"type_of_request must be ask or remove not {req['type_of_request']}"
            }), 400
        business_role_ids = req["business_role_ids"]
        for bri in business_role_ids:
            profile_role = profile_roles.find_one({"profil_role_id" : bri})
            if profile_role is None:
                return jsonify({"status" : "failed", "message" : f"profile role {bri} not found"}), 404
        userid = get_userid_by_token()
        Thread(target = requestThread, args=(req,userid,)).start()
        return jsonify(
            {
                "status" : "success",
                "message" : "Request is now processing"
            }
        )
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/add/profil_role', methods=['PUT'])
def profileRoleAdd():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["ROLE_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to add profil role"
            }), 401
        manager = getUserManager(userid)
        approvers = []
        if manager is not None:
            managerID = manager["uid"]
            approvers.append(managerID)
        userID = req["userid"]
        approvers.extend(getGroupMember(config['ROLE_MGR']))
        task_id = str(ObjectId())
        role_requested = []
        business_role_ids = req["business_role_ids"]
        for bri in business_role_ids:
            profile_role = profile_roles.find_one({"profil_role_id" : bri})
            if profile_role is None:
                return jsonify({"status" : "failed", "message" : f"profile role {bri} not found"}), 404
            tps = []
            for itp in profile_role["id_technical_profil"]:
                itpInfo = technical_profiles.find_one({"technical_profil_id" : itp})
                name = ""
                crtct_lvl = ""
                if itpInfo is not None:
                    name = itpInfo["name"]
                    crtct_lvl = itpInfo["criticity_level"]
                tps.append(
                    {
                        "id" : itp,
                        "name" : name,
                        "criticity_level" : crtct_lvl,
                        "state" : "pending",
                        "validation_state" : "pending" if crtct_lvl <2 else ["no", "no"] 
                    }
                )
            role_requested.append(
                {
                    "state" : "pending",
                    "validation_state" : "pending",
                    "profil_role_id" : profile_role["profil_role_id"],
                    "name" : profile_role["name"],
                    "criticity_level" : profile_role["criticity_level"],
                    "technical_profiles_state" : tps
                }
            )
        tasks.insert_one(
            {
                "applicant": userID,
                "status": "pending",
                "date": datetime.now(),
                "number_of_attempts": 0,
                "type_of_request": "direct_approval",
                "task_id": task_id,
                "role_requested": role_requested,
                "logs": ""
            }
        )
        approval(task_id)
        return jsonify(
            {
                "status" : "success",
                "message" : "Request is now processing"
            }
        )
    except:
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/remove/profil_role', methods=['PUT'])
def profileRoleRemove():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["ROLE_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to add profil role"
            }), 401
        business_role_ids = req["business_role_ids"]
        for bri in business_role_ids:
            profile_role = profile_roles.find_one({"profil_role_id" : bri})
            if profile_role is None:
                return jsonify({"status" : "failed", "message" : f"profile role {bri} not found"}), 404
        userID = req["userid"]
        user = users.find_one({"uid" : userID})
        if user is None:
            return jsonify({
                "status" : "failed",
                "message" : "User not found"
            }), 404
        brs = user["business_roles"]
        for bri in business_role_ids:
            if bri in brs:
                brs.remove(bri)
        users.find_one_and_update(
            {"uid" : userID},
            {
                "$set": {"business_roles" : brs}
            },
            upsert=True
        )
        return jsonify(
            {
                "status" : "success",
                "message" : "Profile removed from " + user["firstname"] + " " + user["lastname"]
            }
        )
    except:
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/profile_role_request/all', methods=['GET'])
def role_request_all():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        userid = get_userid_by_token()
        user_dn = getUserDn(userid)
        user_roles = getUserGroup(user_dn, userid)
        AUTHORIZED = "admin" in user_roles
        response = []
        tprf = technical_profile_requests.find(
            {
                "approver_uid" : userid,
                "state" : {"$ne" : "done"}
            }, 
            {"_id" : 0, "approver_uid" : 0}
        )
        for tpr in tprf:
            creation_date = tpr["creation_date"]
            datetime_date = creation_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["creation_date"] = datetime_date
            
            expiration_date = tpr["expiration_date"]
            datetime_date2 = expiration_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["expiration_date"] = datetime_date2
            response.append(tpr)
        data = response
        if AUTHORIZED:
            others_tprf = technical_profile_requests.find(
                {
                    "state" : {"$ne" : "done"},
                    "approver_uid" : {"$ne" : userid}
                },
                {"_id" : 0, "token" : 0}
            )
            others = []
            for tpr in others_tprf:
                creation_date = tpr["creation_date"]
                datetime_date = creation_date.strftime("%d/%m/%Y %H:%M:%S")
                tpr["creation_date"] = datetime_date
                
                expiration_date = tpr["expiration_date"]
                datetime_date2 = expiration_date.strftime("%d/%m/%Y %H:%M:%S")
                tpr["expiration_date"] = datetime_date2
                others.append(tpr)
            data = {
                "own_requests" : response,
                "other_requests" : others
            }
        default_str = json.dumps(
            {
                "status" : "success",
                "message" : "",
                "data" : data
            },
            indent = 2,
            default = str
        )
        return json.loads(default_str)
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/profile_role_request/history', methods=['GET'])
def role_request_done():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        userid = get_userid_by_token()
        user_dn = getUserDn(userid)
        user_roles = getUserGroup(user_dn, userid)
        AUTHORIZED = "admin" in user_roles
        response = []
        tprf = technical_profile_requests.find({"approver_uid" : userid, "state" : "done"}, {"_id" : 0, "token" : 0, "approver_uid" : 0})
        for tpr in tprf:
            creation_date = tpr["creation_date"]
            datetime_date = creation_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["creation_date"] = datetime_date
            
            expiration_date = tpr["expiration_date"]
            datetime_date2 = expiration_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["expiration_date"] = datetime_date2
            response.append(tpr)
        data = response
        if AUTHORIZED:
            tprf = technical_profile_requests.find(
                {"state" : "done"},
                {"_id" : 0, "token" : 0}
            )
            to_remove = []
            cursor_list = []
            for tpr in tprf:
                if tpr["approver_uid"] == userid:
                    del tpr["approver_uid"]
                    to_remove.append(tpr)
                    cursor_list.append(tpr)
                else:
                    del tpr["approver_uid"]
                    cursor_list.append(tpr)
            for tr in to_remove:
                cursor_list.remove(tr)
            others = []
            for tpr in cursor_list:
                date = tpr["date"]
                datetime_date = date.strftime("%d/%m/%Y %H:%M:%S")
                tpr["date"] = datetime_date
                others.append(tpr)
            data = {
                "own_requests" : response,
                "other_requests" : others
            }
        return json.dumps(
            {
                "status" : "success",
                "message" : "",
                "data" : data
            },
            indent = 2,
            default = str
        )
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/my_request/all', methods=['GET'])
def my_role_request_all():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        userid = get_userid_by_token()
        user_dn = getUserDn(userid)
        response = []
        tprf = tasks.find(
            {
                "type" : "profile_role_request",
                "applicant" : userid,
                "status" : "pending"
            }, 
            {"_id" : 0}
        )
        for tpr in tprf:
            creation_date = tpr["creation_date"]
            datetime_date = creation_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["creation_date"] = datetime_date
            
            expiration_date = tpr["expiration_date"]
            datetime_date2 = expiration_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["expiration_date"] = datetime_date2
            response.append(tpr)
        data = response
            
        return json.dumps(
            {
                "status" : "success",
                "message" : "",
                "data" : data
            },
            indent = 2,
            default = str
        )
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/my_request/history', methods=['GET'])
def my_role_request_done():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        userid = get_userid_by_token()
        user_dn = getUserDn(userid)
        response = []
        tprf = tasks.find(
            {
                "type" : "profile_role_request",
                "applicant" : userid,
                "status" : "done"
            }, 
            {"_id" : 0}
        )
        for tpr in tprf:
            creation_date = tpr["creation_date"]
            datetime_date = creation_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["creation_date"] = datetime_date
            
            expiration_date = tpr["expiration_date"]
            datetime_date2 = expiration_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["expiration_date"] = datetime_date2
            response.append(tpr)
        data = response
            
        return json.dumps(
            {
                "status" : "success",
                "message" : "",
                "data" : data
            },
            indent = 2,
            default = str
        )
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/profile_role_request/<string:token>', methods=['GET'])
def role_request(token):
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        userid = get_userid_by_token()
        response = []
        tprf = technical_profile_requests.find(
            {"approver_uid" : userid, "state" : "pending", "token" : token},
            {"_id" : 0, "token" : 0, "approver_uid" : 0}
        )
        for tpr in tprf:
            creation_date = tpr["creation_date"]
            datetime_date = creation_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["creation_date"] = datetime_date
            
            expiration_date = tpr["expiration_date"]
            datetime_date2 = expiration_date.strftime("%d/%m/%Y %H:%M:%S")
            tpr["expiration_date"] = datetime_date2
            response.append(tpr)
        return json.dumps(
            {
                "status" : "success",
                "message" : "",
                "data" : response
            },
            indent = 2,
            default = str
        )
    except:
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@ORGANIGRAM_REQUEST.route('/user/profil_role/grant_deny/<string:token>', methods=['POST'])
def profileRoleGrantDeny(token):
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        userid = get_userid_by_token()
        user_groups = getUserGroup(getUserDn(userid), uid=userid)
        if not (config["ROLE_MGR"] in user_groups):
            return jsonify({
                "status" : "failed",
                "message" : "Not allowed to create profil role"
            }), 401
        found_token = tokens.find_one({"token" : token})
        if found_token is None:
            return jsonify({
                "status" : "failed",
                "message" : "Invalid token"
            }), 404
        taskid = found_token["task_id"]
        found_task = tasks.find_one({"task_id" : taskid})
        if found_task is None:
            return jsonify({
                "status" : "failed",
                "message" : "Task not found"
            }), 404
        for ar in req["approved_info"]:
            condition = ar["state"] != "approved" and ar["state"] != "rejected"
            if condition:
                invalid_state = ar["state"]
                return jsonify({
                    "status" : "failed",
                    "message" : f"the states must be approved or rejected but state {invalid_state} were found"
                }), 400
        approbation_response = {
            "approver_type" : "other",
            "approver_uid" : userid,
            "approved_info" : req["approved_info"]
        }
        if found_task["approvers"]["manager"] == userid:
            approbation_response["approver_type"] = "manager"
        
        if found_task["approvers"]["manager_manager"] == userid:
            approbation_response["approver_type"] = "manager_manager"
        
        if isErrorKey(found_task, "type_of_request"):
            approbation_response["type_of_request"] = found_task["type_of_request"]
            
        confirm_approval_role(taskid, approbation_response)
        return jsonify(
            {
                "status" : "success",
                "message" : "Request is now processing.."
            }
        )
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400



