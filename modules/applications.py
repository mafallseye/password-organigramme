from flask import Flask, jsonify, request, Blueprint
from flask_swagger_ui import get_swaggerui_blueprint
from bson import ObjectId
import pymongo
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from modules.ldapauth import isErrorKey
from modules.required_packages import validation

client = pymongo.MongoClient("mongodb://db002usr:Hav*1cha@10.0.0.185:27017")
db002 = client['db002']

applications = db002["applications"]
account = db002["account"]
app_account = db002["account"]

def get_data():
    if not request.get_json():
        return jsonify({"message":"missing params", "status": "failed"}),400
    data = request.get_json(force=True)
    return data


APP_REQU = Blueprint("application", __name__)
@APP_REQU.route('/create', methods=['POST'])
def create_app():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    #check if it exists
    try:
        check = applications.find_one({"name" : req["name"]})
        if (check):
            return jsonify({"message":"App " + req["name"] + " already exists", "status": "failed"}),400

        #insert
        date_of_creation = datetime.now()
        app_id = str(ObjectId())
        app_infos = { 
            "app_id": app_id,
            "type": req["type"],
            "name": req["name"],
            "fields":req["fields"],
            "date": date_of_creation
        }
        try:
            applications.insert_one(app_infos)
        except:
            return ({"message": "Cannot create the application", "status": "failed"}),400
        return jsonify({"message": "App " + req["name"] + " created successfully", "app_id": app_id, "type": req["type"], 
        "created the": date_of_creation, "status": "success" }), 200
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@APP_REQU.route('/delete', methods=['DELETE'])
def delete_app():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    find = applications.find_one({"name" : req["name"]})
    applications.delete_one(find)
    return jsonify({"message": "App " + req["name"] + " deleted successfully", "status": "success"}),200

@APP_REQU.route('/account/create', methods=['POST'])
def add_account():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    
    # if not isErrorKey(req["fields"], "admin_username"):
    #     req["fields"]["admin_username"] = req["username"]
    # if not isErrorKey(req["fields"], "admin_password"):
    #     req["fields"]["admin_password"] = req["password"]

    # app = applications.find_one({"app_id":req["app_id"]})    
    # for k,v in app["fields"].items():
    #     try:
    #         if v:
    #             req["fields"][k]
    #     except KeyError:
    #         return jsonify({"message":f"key {k} is required", "status": "failed"}), 400
    
    date_of_creation = datetime.now()
    account_id = str(ObjectId())
    data_to_store = {
        "account_id": account_id,
        "app_id": req["app_id"],
        "user_uid": req["user_uid"],
        "username": req["username"],
        # "password": req["password"],
        "date": date_of_creation
        # "is_expired": False
    }
    try:
        account.insert_one(data_to_store)
        return ({"status":"success", "account_id": account_id}), 200
    except:
        return jsonify({"message": "Failed to create", "status": "failed"}),400

@APP_REQU.route('/all', methods=['GET'])
def getApp():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        apps = applications.find({},{ "_id": 0, "app_id": 1, "name": 1, "type": 1, "date": 1, "fields": 1})
        data = []
        for app in apps:
            accounts = account.find({"app_id": app["app_id"]})
            nb_account = len(list(accounts))
            app["nb_account"] = nb_account
            data.append(app)
        return jsonify({"data":data, "status": "success"}), 200
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}),400

#for admin---
@APP_REQU.route('/account/all', methods=['POST'])
def list_accounts():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        accounts = app_account.find({"app_id" : req["app_id"]}, { "_id": 0})
        list_of_accounts = []
        for i in accounts:
            list_of_accounts.append(i)
        return jsonify({"status":"success","data":list_of_accounts}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}),400

#get all account of all app of user
@APP_REQU.route('/account/user/all', methods=['POST'])
def list_accounts_of_user():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        accounts = app_account.find({"user_uid" : req["user_uid"]})
        list_of_accounts = []
        for i in accounts:
            list_of_accounts.append({i["username"] : i["password"]})
        return jsonify({"status":"success","data":list_of_accounts}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}),400
  
#get all account of an app for an user  
@APP_REQU.route('/account/user', methods=['POST'])
def app_account_of_user():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        accounts = app_account.find({"app_id" : req["app_id"], "user_uid": req["user_uid"]})
        list_of_accounts = []
        for i in accounts:
            list_of_accounts.append({i["username"] : i["password"]})
        return jsonify({"status":"success","data":list_of_accounts}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}),400

@APP_REQU.route('/account/search', methods=['POST'])
def search_account():
    req = get_data()
    app_account = db002["account"]

    try :
        find = app_account.find_one({"app_id" : req["app_id"], "user_uid": req["user_uid"], "username": req["account_username"]})
        if not find:
            return jsonify("")
        account_searched = {find["username"] : find["password"]}
        return jsonify({"status":"success","data":account_searched}),200
    except :
        return jsonify({"message":"Something went wrong!", "status": "failed"}),400
        