import traceback
from flask import jsonify, Blueprint
from pymongo import MongoClient
from modules.required_packages import isErrorKey, run_dag, validation
from bson import ObjectId
import datetime

client = MongoClient("mongodb://db002usr:Hav*1cha@10.0.0.185:27017")
SECRET_REQU = Blueprint("secret", __name__)

db002 = client["db002"]
tasks = db002["tasks"]
secrets = db002["secrets"]
safe = db002["safe"]
creds = db002["creds"]
account = db002["account"]
applications = db002["applications"]
st = db002["secret_type"]
phistory = db002["propagate_history"]

# def finder_checker(collection, search_scope):
#     result = collection.find_one(search_scope)
#     return result

@SECRET_REQU.route('/create', methods=['POST'])
def create_app():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    owner_uid = req["owner_uid"]
    secret_name = req["name"]
    secret = req["secret"]
    safe_id = req["safe_id"]
    secret_type = req["secret_type"]
    try:
        #find secret type
        stf = st.find_one({"name":secret_type})
        if stf is None:
            return jsonify({"status":"failed", "message":f"the secret type {secret_type} isn't defined"}), 400 
        
        already_existing_secret = secrets.find_one({"name" : secret_name, "owner_uid" : owner_uid})
        already_existing_safe = safe.find_one({"safe_id" : safe_id, "owner_uid" : owner_uid})
        if already_existing_secret:
            return jsonify({"message":"secret " + secret_name + " already exists", "status": "failed"}),400
        if not already_existing_safe:
            return jsonify({"message":"the safe does not exist", "status": "failed"}), 400
        secret_id = str(ObjectId())
        date_of_creation = datetime.datetime.now()
        secret_infos = {
            "owner_uid": owner_uid,
            "secret_id": secret_id,
            "name": secret_name,
            "date": date_of_creation,
            "secret_type": "other",
            "safe_id": safe_id
        }
        if secret_type == "file":
            secret_infos["secret_type"] = secret_type
            return jsonify({"status":"comming soon", "message":f"the secret type {secret_type} isn't supported for now comming soon!"})
        
        if secret_type == "credentials":
            secret_infos["secret_type"] = secret_type
            if not isErrorKey(req, "app_type"):
                return jsonify({"status" : "failed", "message": "app_type is required"}), 400
            apt = req["app_type"]
            #find app info
            app_infos = applications.find_one({"type": apt})
            if app_infos is None:
                return jsonify({"status":"failed", "message":f"The application of type {apt} is not defined in azumaril"}), 400
            secret_infos["app_type"] = apt
            if app_infos is not None:
                required_key = []
                for a,b in app_infos["fields"].items():
                    if b:
                        required_key.append(a)
                missing_key = []
            
                for rk in required_key:
                    if rk not in secret:
                        missing_key.append(rk)
            
                if len(missing_key) > 0:
                    return jsonify({"status":"failed", "message":"missing this attributes : " + str(missing_key) +" in the secrets"}), 400 
        
        secret_infos["secret"] = secret
        secrets.insert_one(secret_infos)
        
        return jsonify({
            "status": "success",
            "secret_id": secret_id,
            "created the": date_of_creation
        })
    except:
        print(traceback.format_exc())
        return jsonify({"message": "Cannot create the secret", "status": "failed"}), 400
    

@SECRET_REQU.route('/update', methods=['PUT'])
def update_secret():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:    
        if not isErrorKey(req, "secret_id"):
            return jsonify({"status": "failed", "message": "secret_id is required"}), 400
        sf = secrets.find_one({"secret_id":req["secret_id"]})
        
        secret_id = req["secret_id"]
        
        if sf is None:
            return jsonify({"status": "failed", "message": "bad secret_id or secret isn't existing anymore"}), 400
        safe_id = sf["safe_id"]
        
        if isErrorKey(req, "safe_id"):
            if safe.find_one({"safe_id":req["safe_id"]}) is None:
                return jsonify({"status": "failed", "message": "bad safe_id or safe isn't existing anymore"}), 400
            safe_id = req["safe_id"]
            
        if isErrorKey(req, "name"):
            sfi = secrets.find_one({"name":req["name"], "safe_id":safe_id})
            if sfi is not None:
                name = req["name"]
                return jsonify({"status": "failed", "message": f"there is already a secret with name {name} in safe {safe_id}"}), 400

        if isErrorKey(req, "secret"):
            if sf["secret_type"] == "credentials":
                if type(req["secret"]) != dict:
                    return jsonify({"status": "failed", "message": "the secret field must be an object"}), 400
                for k,v in req["secret"].items():
                    if k not in sf["secret"]:
                        return jsonify({"status": "failed", "message": f"key {k} is not in secret value so you can't update it"}), 400
        del req["secret_id"]
        secrets.find_one_and_update(
            {'secret_id':secret_id},
            { '$set': req }
        )
        return jsonify({"status": "success", "message": f"the secret {secret_id} updated successfully"}), 400
    except:
        print(traceback.format_exc())
        return jsonify({"status": "failed", "message": "Something went wrong"}), 400

@SECRET_REQU.route('/delete', methods=['DELETE'])
def delete_secret():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    if not isErrorKey(req, "secret_id"):
        return jsonify({"status": "failed", "message": "secret_id is required"}), 400
    secret_id = req["secret_id"]
    if secrets.find_one({"secret_id":req["secret_id"]}) is not None:
        secrets.delete_one({"secret_id":req["secret_id"]})
        return jsonify({"status": "success", "message": f"the secret {secret_id} deleted successfully"})
    else:
        return jsonify({"status": "failed", "message": "bad secret_id or secret already deleted"}), 400
    
@SECRET_REQU.route('/all', methods=['POST'])
def get_secrets():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        user_secrets = secrets.find({"owner_uid": req["owner_uid"]}, {"_id": 0,})
        list_of_secrets = []
        for secret in user_secrets:
            list_of_secrets.append(secret)
        return jsonify({"status":"success","data":list_of_secrets}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}), 400

@SECRET_REQU.route('/safe/create', methods=['POST'])
def safe_create():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    owner_uid = req["owner_uid"]
    safe_name = req["name"]

    check = safe.find_one({"name" : safe_name})
    if check :
        return jsonify({"message":"safe " + safe_name + " already exists", "status": "failed"}), 400
    safe_id = str(ObjectId())
    date_of_creation = datetime.datetime.now()
    safe_info = {"owner_uid": owner_uid, "safe_id": safe_id, "name": safe_name, "date": date_of_creation}
    try:
        safe.insert_one(safe_info)
    except:
        return jsonify({"message": "Cannot create the safe", "status": "failed"}),400
    return jsonify({"status": "success", "safe_id": safe_id, "created the": date_of_creation }),200
    
@SECRET_REQU.route('/safe/all', methods=['POST'])   #ADMIN
def safe_all():
    validated = validation()
    if not validated[0]:
        return validated[1]
    try:
        safes = safe.find({}, {"_id": 0,})
        data = []
        for us in safes:
            data.append(us)
        return jsonify({"status":"success", "safes":data}),200
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400
    
@SECRET_REQU.route('/safe/safe_secrets', methods=['POST'])
def safe_secrets():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        safe_secrets = secrets.find({"safe_id" : req["safe_id"], "owner_uid": req["owner_uid"]}, {"_id":0})
        list_of_secrets = []
        for secret in safe_secrets:
            list_of_secrets.append(secret)
        return jsonify({"status":"success","data":list_of_secrets}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}), 400
    
@SECRET_REQU.route('/types', methods=['GET'])
def secretTypes():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        stf = st.find({}, {"_id":0})
        list_of_stf = []
        for secret in stf:
            list_of_stf.append(secret)
        return jsonify({"status":"success","data":list_of_stf}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}), 400

@SECRET_REQU.route('/user/safe/all', methods=['POST'])
def user_safe_all():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        user_safes = safe.find({"owner_uid":req["owner_uid"]}, {"_id": 0,})
        data = []
        for us in user_safes:
            data.append(us)
        return jsonify({"status":"success", "data":data}),200
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400
    
@SECRET_REQU.route('/propagate', methods=['POST'])
def propagate():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        user_secret = secrets.find_one({"secret_id":req["user_secret_id"]})
        if user_secret is None:
            return jsonify({"status":"failed", "message":"user_secret_id is incorrect or secret does not exist"}), 400
        else:
            typeuser = applications.find_one({"type": user_secret["app_type"]})
            if typeuser is None:
                errType = user_secret["app_type"]
                return jsonify({"status":"failed", "message": f"The propagation of the {errType} type is not supported by azumaril"}), 400
        
        admin_secret = secrets.find_one({"secret_id":req["admin_secret_id"]})
        if admin_secret is None:
            return jsonify({"status":"failed", "message":"admin_secret_id is incorrect or secret does not exist"}), 400
        else:
            typeadm = applications.find_one({"type":admin_secret["app_type"]})
            if typeadm is None:
                errType = admin_secret["app_type"]
                return jsonify({"status":"failed", "message": f"The propagation of the {errType} type is not supported  by azumaril"}), 400
        if admin_secret["app_type"] != user_secret["app_type"]:
            return jsonify({"status":"failed", "message":"application type of the secrets are not of the same, can't propagate "+ user_secret["app_type"] + "to " + admin_secret["app_type"]}), 400
        
        if admin_secret["secret_type"] != user_secret["secret_type"]:
            return jsonify({"status":"failed", "message":"the secrets are not of the same type, can't propagate "+ user_secret["secret_type"] + "to " + admin_secret["secret_type"]}), 400
        if admin_secret["secret_type"] == "credentials":
            taskid = str(ObjectId())
            tasks.insert_one({
                "taskid":taskid,
                "type": admin_secret["app_type"]+"_propagate",
                "user_secret_id":req["user_secret_id"],
                "admin_secret_id":req["admin_secret_id"],                            
                "account_id":req["account_id"],
                "status":"pending"
            })
            run_dag(taskid)
            return jsonify({"status":"success", "message":"secret is now spreading"}),200
        else:
            sct = admin_secret["secret_type"]
            return jsonify({"message":f"the propagation of secret type {sct} is not yet supported by azumaril coming soon..", "status":"failed"}),400
    except:
        return jsonify({"message":"Something went wrong!", "status":"failed"}),400

@SECRET_REQU.route('/propagate_history', methods=['POST'])
def propagate_history():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        History = phistory.find({"uid": req["uid"]})
        userHistory = []
        for doc in History:
            del doc["_id"]
            userHistory.append(doc)
        results = {
            "status": "success",
            "data": userHistory,
        }
        return jsonify(results),200
    except:
        return jsonify({"message":"Something went wrong!", "status":"failed"}),400
