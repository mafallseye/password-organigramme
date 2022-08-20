from genericpath import exists
import random
from textwrap import indent
from threading import Thread
import traceback
from flask import redirect, request,jsonify, Blueprint, json
from modules.required_packages import encode_token, get_userid_by_token, policy, run_dag, mail_sender, generate_code, validMail, validation, encode_auth_token
from ldap3 import LEVEL, MODIFY_ADD, MODIFY_REPLACE, Server, Connection, ALL, SUBTREE, NTLM, HASHED_SALTED_SHA
from ldap3.utils.hashed import hashed
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups
from flask_ldap3_login import LDAP3LoginManager
import ast
import pymongo
import pyotp
import os
from bson import ObjectId

client = pymongo.MongoClient("mongodb://db002usr:Hav*1cha@10.0.0.185:27017")
db002 = client['db002']
creds = db002["creds"]
FA2 = db002["2FA"]
FA2info = db002["info2FA"]
users = db002["users"]
tasks = db002["tasks"]
tokens = db002["tokens"]

ldap_server = creds.find_one({"type":"ldap"},{"_id":0})
server = Server(ldap_server["url"], get_info=ALL)
ldap = Connection(
    server,
    user=ldap_server["value"]["default_user_dn"],
    password=ldap_server["value"]["default_password"]
)

ldapState = ldap.bind()
print(ldapState)
config = dict()
config['LDAP_HOST'] = ldap_server["url"]
config['LDAP_BASE_DN'] = ldap_server["value"]["base_dn"]
config['LDAP_USER_DN'] = ldap_server["value"]["user_dn"]
config['LDAP_GROUP_DN'] = ldap_server["value"]["group_dn"]

readonly_group = ldap_server["value"]["readonly"]

ldap_manager = LDAP3LoginManager()
ldap_manager.init_config(config)

LDAP_REQUEST = Blueprint('ldap_request', __name__)

def getUserDn(uid):
    DN ='uid=' + uid + ',' + config['LDAP_USER_DN'] + ',' + config['LDAP_BASE_DN']
    return DN

def getGroupDn(cn):#cn=readonly,ou=groups,dc=axetag,dc=com
    DN ='cn=' + cn + ',' + config['LDAP_GROUP_DN'] + ',' + config['LDAP_BASE_DN']
    return DN

def get_all_groups():
    search_dn = config['LDAP_GROUP_DN'] +','+ config['LDAP_BASE_DN']
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
        # if key == "managerID":
        #     default["manager"] = default["manager"] if condition else getUserDn(value)
    
    for key, value in default.items():
        if type(value) == type(""):
            ldap.modify(user_dn, {key: [(MODIFY_REPLACE, [value])]})
         
    search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']       
    afterMod = get_userInfo(search_dn, uid)
    displayName = afterMod["cn"][0] + " " + afterMod["sn"][0]
    ldap.modify(user_dn, {"displayName": [(MODIFY_REPLACE, [displayName])]})

def getUsers():
    if not ldapState:
        return None
    search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
    response = ldap.search(
        search_base = search_dn,
        search_filter = '(objectClass=person)',
        attributes = ["uid","cn","sn","displayName","manager"],
        dereference_aliases = "ALWAYS"
    )
    entry = ldap.entries
    all_users = []
    for user in entry:
        user_data = json.loads(user.entry_to_json())
        if user_data["attributes"]["uid"][0] != "admin":
            info = {
                "cn" : user_data["attributes"]["cn"][0],
                "sn" : user_data["attributes"]["sn"][0],
                "uid" : user_data["attributes"]["uid"][0]
            }
            try:
                if len(user_data["attributes"]["displayName"]) != 0:
                    info["displayName"] = user_data["attributes"]["displayName"][0];
                if len(user_data["attributes"]["manager"]) != 0:
                    info["manager"] = user_data["attributes"]["manager"][0];
            except KeyError:
                pass
            
            all_users.append(info)
    if response:
        organigram = []
        no_manager = []
        has_manager = []
        for user in all_users:
            try:
                user["manager"]
                has_manager.append(getFils(user,all_users))
            except  KeyError:
                no_manager.append(getFils(user,all_users))
        organigram = [no_manager, has_manager]
        # for nm in no_manager:
        #     for fils in nm["fils"]:
        #         ffs = getFils(fils,all_users)["fils"]
        #         fils["fils"] = ffs
        # return json.dumps({"organigram":organigram}, indent=2)
        return all_users
    else:
        return None

def getFils(user, all_users):
    user_info = {
        "info" : user,
        "fils" : [] #come back
    }
    for user_fils in all_users:
        try:
            if user_fils["manager"] == getUserDn(user["uid"]):
                user_info["fils"].append(user_fils)  
        except KeyError:
            pass
    return user_info
   
def userChild(uid):
    search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
    all_users = getUsers()
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
    }
    if len(uinfo["telephoneNumber"]) != 0:
        data["telephoneNumber"] = uinfo["telephoneNumber"][0]
    if len(uinfo["businessCategory"]) != 0:
        data["businessCategory"] = uinfo["businessCategory"][0]
    if len(uinfo["manager"]) != 0:
        managerID = uinfo["manager"][0].split(",")[0].split("=")[1]
        data["managerID"] = managerID
    userFils = getFils(data, all_users)
    return userFils
      
def getUserManager(uid):
    all_users = getUsers()
    all_user_info = []
    for user in all_users:
        all_user_info.append(userChild(user["uid"]))
    for user2 in all_user_info:
        for fils in user2["fils"]:
            if fils["uid"] == uid:
                return user2["info"]   
    return None   

def send2FA_code(mail, user_uid):
    try:
        # generating random PyOTP secret keys
        totp_secret = pyotp.random_base32()
        qr_url = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=mail, issuer_name='Azumaril')
        FA2.insert_one({"uid":user_uid, "otp_secret":totp_secret, "mail":mail, "qr_url":qr_url})
        #-----this is for test purpose
        #-----Display the qr code in the terminal
        comand = "qr "+ qr_url
        print(comand)
        os.system(comand)
        #------------ 
        return {"uid":user_uid, "mail":mail, "otp_secret":totp_secret, "qr_url":qr_url}
    except:
        return None

def user_exists(userID):
    entry = ldap.search('uid=' + userID + ',' + config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
    , '(objectclass=person)')
    if entry:
        return True
    return False

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

def getLastUid():
    search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
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

def get_sequence():
    all_seq = db002["uid_seq"]
    old_seq = all_seq.find().sort([('seq', -1)]).limit(1)
    try:
        old_seq[0]
    except:
        new = new_seq("")
        all_seq.insert_one({"seq": new})
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

def isErrorKey(user, key):
    try:
        user[key]
        return True and user[key] != ""
    except KeyError:
        return False
  
def getUserGroup(user_dn, uid=""):
    search_dn2 = config['LDAP_GROUP_DN'] +','+ config['LDAP_BASE_DN']
    ldap.search(search_dn2, f'(|(member={user_dn})(memberUid={uid}))')
    groups = []
    for entry in ldap.entries:
        group = ast.literal_eval(entry.entry_to_json())
        groups.append(group['dn'].split(",")[0].split("=")[1])
    return groups
   
def changePassword(user_dn, req, isReseting=False):
    if not isErrorKey(req, "newPassword"):
        return jsonify({"message":"newPassword is required", "status": "failed"}), 400
    hashed_password = hashed(HASHED_SALTED_SHA, req["newPassword"])
    if isReseting:
        taskid = str(ObjectId())
        tasks.insert_one({
            "taskid" : taskid,
            "type" : "ldap_change",
            "user_dn" : user_dn,
            "newPassword" : hashed_password,
            "admin_dn": ldap_server["value"]["default_user_dn"],
            "admin_password":ldap_server["value"]["default_password"],
            "admin_mod" : "yes",
            "status":"pending"
        })
        run_dag(taskid)
        return jsonify({"status":"success","message":"change password request is now processing.."})
    else:
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
            return jsonify({"status":"success","message":"change password request is now processing.."})
        else:
            return jsonify({"message":"Unable to change password, old password is incorect or bad user uid", "status": "failed"}) ,400

def tryConnexion(user_uid, password):
    user_dn = getUserDn(user_uid)
    result = Connection(
        server,
        user = user_dn,
        password = password
    )
    return result.bind()

@LDAP_REQUEST.route("/2FA/register",  methods=['POST'])
def register_2fa():
    try:
        validated = validation()
        if not validated[0]:
            return validated[1]
        req = validated[1]
        
        user_uid = get_userid_by_token()
        user_2fa = FA2info.find_one({"uid":user_uid})
        
        if user_2fa["2fa"] != "no":
            return jsonify({
                "status" : "failed",
                "message" : f"User {user_uid} has already set double authentication"
            }), 400
        
        required_keys = ["password"]
        for rk in required_keys:
            if not isErrorKey(req, rk):
                return jsonify({
                    "status" : "failed",
                    "message" : f"{rk} is required"
                }), 400
                
        userFA2info = FA2.find_one({"mail" : user_2fa["mail"]})
        if userFA2info is not None:
            if not tryConnexion(user_uid, req["password"]):
                return jsonify({
                    "status" : "failed",
                    "message" : "Authentication failed"
                }), 401
            comand = "qr "+ userFA2info["qr_url"]
            print(comand)
            os.system(comand)
            #------------ 
            return jsonify({
                "status" : "success",
                "message" : "User has already qr code to scan",
                "data" : {
                    "otp_secret":userFA2info["otp_secret"],
                    "qr_url":userFA2info["qr_url"]
                }
            })
         
                
        user_dn = getUserDn(user_uid)
        if not tryConnexion(user_uid, req["password"]):
            return jsonify({
                "status" : "failed",
                "message" : "Authentication failed"
            }), 401
            
        user_info = get_userInfo(user_dn ,user_uid)
        mail = user_info["mail"][0]
        data = send2FA_code(mail, user_uid)
        if data is None:
            return jsonify({"message":"Something went wrong", "status": "failed"}), 400
        # FA2info.find_one_and_update({"mail":mail},{'$set': { "2fa" : 'yes'}})
        return jsonify(
            {
                "response":"2FA code sent!",
                "data":{
                    "mail":data["mail"],
                    "totp_secret":data["otp_secret"],
                    "qr_url":data["qr_url"]
                }
            }
        )
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@LDAP_REQUEST.route("/2FA/deactivate",  methods=['PUT'])
def deactivate_2fa():
    try:
        validated = validation()
        if not validated[0]:
            return validated[1]
        req = validated[1]
        user_uid = get_userid_by_token()
        user_2fa = FA2info.find_one({"uid":user_uid})
        required_keys = ["password"]
        for rk in required_keys:
            if not isErrorKey(req, rk):
                return jsonify({
                    "status" : "failed",
                    "message" : f"{rk} is required"
                }), 400
        if user_2fa["2fa"] != "yes":
            if not tryConnexion(user_uid, req["password"]):
                return jsonify({
                    "status" : "failed",
                    "message" : "Authentication failed"
                }), 401
            return jsonify({
                "status" : "failed",
                "message" : f"User {user_uid} has already deactivate double authentication"
            }), 400
        
        if not tryConnexion(user_uid, req["password"]):
            return jsonify({
                "status" : "failed",
                "message" : "Authentication failed"
            }), 401
        
        FA2info.find_one_and_update(
            {"uid" : user_uid},
            {
                '$set': {"2fa" : "no"}
            }
        )
        FA2.find_one_and_delete(
            {"mail" : user_2fa["mail"]}
        )
        return jsonify({
           "status" : "success",
           "meassage" : "Double authentication successfully deactivated" 
        })
    except:
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@LDAP_REQUEST.route("/login",  methods=['POST'])
def ldap_connect(is_search=False):
    req_data = get_data()
    if req_data is None:
        return jsonify({"message":"Missing params", "status": "failed"}), 400
    if not isErrorKey(req_data, "uid"):
        return jsonify({
            "status" : "failed",
            "message" : "uid is required"
        }), 400
    uid = req_data["uid"]
    foundUser = users.find_one({"uid" : uid})
    if foundUser is None :
        foundUser = users.find_one({"email" : uid})
        if foundUser is None :
            return jsonify({
                "status" : "failed",
                "message" : "bad uid or email"
            }), 400
    if not foundUser["is_activated"]:
        return jsonify({
            "status" : "failed",
            "message" : "Account not activated yet, please activate account and retry"
        }), 400
    search_dn1 = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
    uid = foundUser["uid"]
    user_dn = 'uid=' + uid + ',' + search_dn1
    result = Connection(
        server,
        user = user_dn,
        password = req_data["password"]
    )
    if result.bind():
        try:
            fa2 = FA2info.find_one({"uid":uid})
            if fa2 is None:
                fa22 = "no"
            else:
                fa22 = fa2["2fa"]
        except:
            return jsonify({"message":"Authentication failed, this user has no email", "status": "failed"}), 400
        response = {
            "status" : "success",
            "message" : "Successfully authenticated",
            "2FA" : fa22
        }
        if fa22 == "no":
            groups = getUserGroup(user_dn, uid)
            user_info = {}
            for k, v in get_userInfo(user_dn, uid).items() :
                try :
                    user_info[k] = v[0]
                except :
                    user_info[k] = ""
            response["token"] = encode_auth_token(uid)["token"]
            response["user_groups"] = groups
            response["user_info"] = user_info
        else:
            response["uid"] = uid
        
        return json.dumps(
            response, 
            indent = 2
        )
    else:
        return jsonify({"message":"Authentication failed", "status": "failed"}), 400

@LDAP_REQUEST.route("/logout",  methods=['POST'])
def ldap_deconnect():
    try:
        auth_token = request.headers.get('Authorization')
        token = auth_token.split()[1]
        user_token = tokens.find_one({"token":token})
        user_uid = user_token["user_uid"]
        query = {"user_uid": user_uid}
        tokens.delete_many(query)
        return jsonify({"message":"User successfuly logged out", "status":"success"}),200
    except:
        return jsonify({"message":"Something went wrong, may be you're already logged out", "status": "failed"}), 400

@LDAP_REQUEST.route("/change/password",  methods=['POST'])
def change_password():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    user_dn = getUserDn(req["uid"])
    return changePassword(user_dn, req)

@LDAP_REQUEST.route("/change/password/<string:token>",  methods=['PUT'])
def change_password_token(token):
    req = get_data()
    tok = tokens.find_one({"token":token})
    if tok is None:
        return jsonify({"message": "Invalid token please retry", "status": "failed"}), 400
    user_dn = getUserDn(tok["user_uid"])
    return changePassword(user_dn, req, True)

@LDAP_REQUEST.route("/activation",  methods=['PUT'])
def account_activation():
    req = get_data()
    if not isErrorKey(req, "uid"):
        return jsonify({
            "status" : "failed",
            "message" : "uid is required"
        }), 400
    if not isErrorKey(req, "activation_code"):
        return jsonify({
            "status" : "failed",
            "message" : "activation_code is required"
        }), 400
    activation_code = req["activation_code"]
    tok = tokens.find_one({"type" : "activation", "user_uid" : req["uid"], "activation_code" : str(activation_code)})
    if tok is None:
        return jsonify({"message": "Invalid code please retry", "status": "failed"}), 400
    try:
        users.find_one_and_update(
            {"uid" : tok["user_uid"]},
            {'$set': {"is_activated" : True}}
        )
        token = encode_auth_token(tok["user_uid"])["token"]
        user_dn = getUserDn(tok["user_uid"])
        user_info = {}
        for k, v in get_userInfo(user_dn, tok["user_uid"]).items():
            try :
                user_info[k] = v[0]
            except :
                user_info[k] = ""
        groups = getUserGroup(user_dn, tok["user_uid"])
        return jsonify({
            "status" : "success",
            "meassage" : f"Account successfully activated",
            "token" : token,
            "data" : user_info,
            "user_groups":groups
        })
    except:
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@LDAP_REQUEST.route("/forgot/password",  methods=['POST'])
def forgot_password():
    req = get_data()
    try:
        if isErrorKey(req, 'uid'):
            uid = req["uid"]
        else:
            return jsonify({"message": "uid is required", "status": "failed"}), 400
        search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
        uinfo = get_userInfo(search_dn, uid)
        if uinfo is None:
            return jsonify({"message": "bad uid or this user has no mail please set one", "status": "failed"}), 400
        mail = uinfo["mail"][0]
        objet = "Password reset"
        message = "Pour changer votre mot de passe cliquer ici \nserver/api/v1/auth/change/password/" + encode_auth_token(uid)["token"]
        Thread(target = mail_sender, args=(uinfo["mail"][0], objet, message,)).start()
        return jsonify({"status":"success","message":f"email sent to {mail}"})
    except:
        print(traceback.format_exc())
        return jsonify({"message": "Something went wrong", "status": "failed"}),400

@LDAP_REQUEST.route("/admin/change/password",  methods=['POST'])
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

@LDAP_REQUEST.route("/2FA/login",  methods=['POST'])
def ldap_2fa(is_search=False):
    req_data = get_data()
    if not isErrorKey(req_data, "uid"):
        return jsonify({
            "status" : "failed",
            "message" : "uid is required"
        }), 400
    user_uid = req_data["uid"]
    fa2 = FA2info.find_one({"uid":user_uid})
    if fa2 is None:
        return jsonify({
            "status" : "failed",
            "message" : "User not found"
        }), 404
    else:
        fa22 = fa2["2fa"]
        userFA2info = FA2.find_one({"mail" : fa2["mail"]})
        if fa22 == "no" and userFA2info is None:
            return jsonify({
                "status" : "failed",
                "message" : "This user has not set double factor authentication"
            }), 400
    
    mail = fa2["mail"]
    print(mail)
    
    #----get 2fa secret url
    fa2Info = FA2.find_one({"mail":mail})
    if fa2Info is None:
        return jsonify({"message":"Authentication failed, bad email", "status": "failed"}), 400
    qr_url = dict(fa2Info)["qr_url"]
    #----
    
    #----time-based one time password (totp)
    code = req_data["code"]             #this is provided by google authenticator app
    totp = pyotp.parse_uri(qr_url)      #instantiate pyotp class by parsing 2fa secret url
    fa2totp_status = totp.verify(code)  #finaly verify and fa2totp_status is true or false
    if not fa2totp_status:
        return jsonify({"message":"Authentication failed, bad 2FA otp", "status": "failed"}), 400
    fa22 = fa2["2fa"]
    print(fa22)
    if fa22 == "no":
        FA2info.find_one_and_update(
            {"mail":mail},
            {
                "$set": {"2fa" : "yes"}
            },
            upsert=True
        )
    user_dn = getUserDn(user_uid)
    groups = getUserGroup(user_dn, user_uid)
    user_info = {}
    for k, v in get_userInfo(user_dn, user_uid).items() :
        try :
            user_info[k] = v[0]
        except :
            user_info[k] = ""
    token = encode_auth_token(user_uid)["token"]
    response = {
        "status":"success",
        "message":"Double factor authentication success",
        "token" : token,
        "user_groups":groups,
        "user_info" : user_info
    }
    return jsonify(response)
     
@LDAP_REQUEST.route('/register', methods=['POST'])
def RegisterLdap():
    user = get_data()
    if user is None:
        return jsonify({"message":"Missing params", "status": "failed"}), 400
    # response = ldap_manager.authenticate(user["uid"], user["password"])
    #userID = (user['firstname'][0]+user['lastname']).lower()
    userID = unique_uid()
    user_dn = 'uid=' + userID + ',' + config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
    
    if not isErrorKey(user, "firstname") and not isErrorKey(user, "lastname"):
        return jsonify({"message":"firstname and lastname is required", "status": "failed"}),400
    
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
            managerID = 'uid=' + user['managerID'] + ',' + config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
            attributes['manager'] =  managerID
        if hasBusinessCategory:
            attributes['businessCategory'] =  user['businessCategory']
        if hasTel:
            attributes['telephoneNumber'] = user["tel"]
            
        object_class = ['inetOrgPerson','posixAccount','shadowAccount','person']    
        #add user
        result = ldap.add(
            dn = user_dn,
            object_class = object_class,
            attributes = attributes
        )
        if result:
            FA2info.insert({"uid":userID, "2fa":fa2, "mail":user["email"]})
            users.insert_one(
                {
                    "uid" : userID,
                    "email" : user["email"],
                    "firstname" : user["firstname"],
                    "lastname" : user["lastname"],
                    "is_activated" : False,
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
                    send2FA_code(user["email"], userID)
            addUsersInGroups(ldap, user_dn, readonly_group)
            fixed_digits = 6 
            activation_code = str(random.randrange(100000, 999999, fixed_digits))
            encode_token("activation", userID, {"activation_code" : activation_code}, 30)
            mail = user["email"]
            objet = "Azumaril account activation"
            message = f"Voici votre code d'activation : {activation_code} ,\n voici votre identifiant : {userID}"
            Thread(target = mail_sender, args=(mail, objet, message,)).start()
            return jsonify(
                {
                    "status" : "success",
                    "message" : "Account " + fullname + " created successfully",
                    "uid" : userID
                }
            )
        else:
            return jsonify({"message": "Something went wrong", "status": "failed"}),400
        
    except LDAPException as e:
        response = e
        return response

@LDAP_REQUEST.route('/update', methods=['POST'])
def updateUser():
    validated = validation()
    if not validated[0]:
        return validated[1]
    user = validated[1]
    search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
    try:
        uid = user["uid"]
    except:
        return jsonify({"message":"uid is required", "status": "failed"}), 400
    default = get_userInfo(search_dn, uid)
    
    try:
        updateAttributes(default, user)
        return jsonify({"status":"success"}), 200
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

