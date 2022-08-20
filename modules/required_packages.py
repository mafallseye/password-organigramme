import hashlib
import random
import re
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import jsonify, request
import pymongo
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import jwt
import requests
from password_strength import PasswordPolicy

client = pymongo.MongoClient("mongodb://db002usr:Hav*1cha@10.0.0.185:27017")
db002 = client['db002']
creds = db002["creds"]
password_expiration = 90
credsData = creds.find({"type":"token_secret"})[0]
salt = credsData["salt"]
tokens = db002["tokens"]
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
validated_status = True
logs = db002["logs"]
logs_code = db002["logs_code"]
users = db002["users"]
tokSecret = creds.find_one({"type":"token_secret"})

class Validator:
    def __init__(json_cred):
        mail = json_cred["email"]

    def validate_email(self):
        if re.fullmatch(regex, self.email):
            validated_status = False
            print(self.mail)
            return ("{} : Invalid email".format(self.mail))
    def get_status(self):
        return (validated_status)

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
    
class Logs:
    def createLog(self, log_type, message, logModule, logFunction, logCode):
        userid = get_userid_by_token()
        date = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
        ipaddr = request.remote_addr
        logs.insert_one({
            "type" : log_type,
            "message" : message,
            "date" : date,
            "logModule" : logModule,
            "logFunction" : logFunction,
            "logCode" : logCode,
            "userid" : userid,
            "ip_adress" : ipaddr
        })
        user = users.find_one({"uid":userid})
        logMode = user["log_mode"] if user is not None else None
        return userid, date, logMode, ipaddr
    
    def warning(self, message, logModule, logFunction):
        logCode = logs_code.find_one({"type":"warning","module":logModule,"function":logFunction})
        log = self.createLog("warning", message, logModule, logFunction, logCode["code"])
        userid = log[0]
        date = log[1]
        ipaddr = log[3]
        if log[2] is not None and log[2]["warning"]:
            print('\033[93m' + f"{ipaddr} - - [{date}] - DEBUG : {message} in /{logModule}/{logFunction} user : {userid}" + '\033[0m')
    
    def debug(self,message, logModule, logFunction):
        logCode = logs_code.find_one({"type":"debug","module":logModule,"function":logFunction})
        log = self.createLog("debug", message, logModule, logFunction, logCode["code"])
        userid = log[0]
        date = log[1]
        ipaddr = log[3]
        if log[2] is not None and log[2]["debug"]:
            print(f"{ipaddr} - - [{date}] - DEBUG : {message} in /{logModule}/{logFunction} user : {userid}")
    
    def error(self,message, logModule, logFunction):
        logCode = logs_code.find_one({"type":"error","module":logModule,"function":logFunction})
        log = self.createLog("error", message, logModule, logFunction, logCode["code"])
        userid = log[0]
        date = log[1]
        ipaddr = log[3]
        if log[2] is not None and log[2]["error"]:
            print("\033[0;31m"  + f"{ipaddr} - - [{date}] - ERROR : {message} in /{logModule}/{logFunction} user : {userid}" + '\033[0m')
    
    def success(self,message, logModule, logFunction):
        logCode = logs_code.find_one({"type":"success","module":logModule,"function":logFunction})
        log = self.createLog("success", message, logModule, logFunction, logCode["code"])
        userid = log[0]
        date = log[1]
        ipaddr = log[3]
        if log[2] is not None and log[2]["success"]:
            print("\033[0;32m" + f"[{date}] - - {ipaddr} - SUCCESS : {message} in /{logModule}/{logFunction} user : {userid}" + '\033[0m')

def encode_token(token_type, user_uid, data, exp_days):
    token= db002["tokens"] 
    tokenTmp =  {"token": "xxxxxxxxxxxxxxxxxxxxxx","user_uid": "","creation_date": "","expiration_date": "","is_expired": "true"}
    try:
        creation_date_time = datetime.utcnow()
        expiration_date_time = creation_date_time + timedelta(hours=exp_days*24)
        payload = {
            'exp': expiration_date_time,
            'iat': datetime.utcnow(),
            'sub': user_uid
        }
        encodejwt = jwt.encode(
            payload,
            salt,
            algorithm='HS256'
        ).decode('utf8')
        tokenTmp['type'] = token_type
        tokenTmp['token'] = encodejwt
        tokenTmp['user_uid'] = user_uid
        tokenTmp['creation_date'] = creation_date_time
        tokenTmp['expiration_date'] = expiration_date_time
        tokenTmp['is_expired'] = "false"
        tokenTmp.update(data)
        token.insert_one(tokenTmp)
        return tokenTmp
    except Exception as e:
        return e

def encode_auth_token(user_uid):
    """
    Generates the Auth Token
    :return: string
    """  
    token= db002["tokens"] 
    tokenTmp =  {"token": "xxxxxxxxxxxxxxxxxxxxxx","user_uid": "","creation_date": "","expiration_date": "","is_expired": "true"}
    try:
        creation_date_time = datetime.utcnow()
        expiration_date_time = creation_date_time + timedelta(
            hours = tokSecret["time"]["task_token"]*24
        )
        payload = {
            'exp': expiration_date_time,
            'iat': datetime.utcnow(),
            'sub': user_uid
        }
        encodejwt = jwt.encode(
            payload,
            salt,
            algorithm='HS256'
        ).decode('utf8')
        tokenTmp['type'] = "auth_token"
        tokenTmp['token'] = encodejwt
        tokenTmp['user_uid'] = user_uid
        tokenTmp['creation_date'] = creation_date_time
        tokenTmp['expiration_date'] = expiration_date_time
        tokenTmp['is_expired'] = "false"
        token.insert_one(tokenTmp)
        return tokenTmp
    except Exception as e:
        return e

def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, salt)
        fr = tokens.find_one({"user_uid":payload['sub']})
        if fr is None:
            return 'Invalid token. Please log in again.'
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
class ResponseJson:
    def invalid_input(self,error):
        return False,(jsonify({"status":"Failed","message":error}),400)
    
    def requestValidate(self, allowNullData=False):
        if not request.get_json(): #if there isn't json in request body
            if not allowNullData:
                return self.invalid_input("Missing parameters") 
            else:
                return True,0

        data = request.get_json(force=True)
        for key,value in data.items():  #check values and keys of the array
            if not allowNullData:       #do this if None value not allowed
                if value == None:
                    return self.invalid_input(key+" is required")
                if not value:
                    return self.invalid_input(key+" is required")
            else:                       #else do that 
                pass
        return True,data
    def success(self,data):
        return jsonify({"data":data,"status":"success"})
    def IndexError(self,message):
        return jsonify({"message":message, "status": "failed"}),401
    def TypeError(self,message):
        return jsonify({"message":message, "status": "failed"}),400
    def DuplicateKeyError(self,message):
        return jsonify({"message":message, "status": "failed"}),409
    def e404(self,message):
        return jsonify({"message":message, "status": "failed"}),404
resJson = ResponseJson()
def tokenValidation():
    auth_token = request.headers.get('Authorization')
    if auth_token is not None:
        auth_token = auth_token.split()[1]
        fouundToken = tokens.find_one({"type" : "auth_token", "token" : auth_token})
        if fouundToken is None:
            return {"status":False, "message": "The token is not an authentication token, please login again"}
        try:
            token_validation_message = decode_auth_token(auth_token)
            signature_expired = token_validation_message == 'Signature expired. Please log in again.'
            invalid_token = token_validation_message == 'Invalid token. Please log in again.'
            if signature_expired or invalid_token:
                return {"status":False,"message":token_validation_message}
        except:
            return {"status":False,"message":token_validation_message}
        return {"status":True,"message":token_validation_message}
    else:
        return {"status":False,"message":"missing token"}

def validation(allowNullData=False):
    validate = tokenValidation()
    if validate["status"]:
        validated = resJson.requestValidate(allowNullData)
        return validated
    else:
        return False,(jsonify({"message":validate["message"], "status": "failed"}),401)
    
def airflow_to_send_mail(taskid):
    endPoint = creds.find_one({"endpoint":"airflow"})
    URL = endPoint["url"] + "/api/v1/dags/send_mail/dagRuns"
    try:
        me = creds.find_one({'type': 'altara_airflow_prod'})
        data = "{\"conf\": {\"taskid\":\""+taskid+"\"}, \"dag_run_id\": \""+"airflow_"+taskid + str(random.random()) +"\" }"
        headers = {'Content-Type': 'application/json', 'accept': 'application/json' }
        results = request.post(URL, data, auth=(me["username"], me["password"]), headers=headers)
        if results.status_code == 200:
            return "ok", 200
        else: return "something went wrong", results.status_code
    except Exception as err:
        return err
    
def mail_sender(receiver,subject,message):
    """
    Generates the Auth Token
    :return: string
    """  
    smtpData= db002["smtp"] 
    retreiveSmtpData=smtpData.find_one({},{"_id":0})
    msg = MIMEMultipart()
    msg['From'] = retreiveSmtpData["from"]
    msg['To'] = receiver
    msg['Subject'] = subject
    msg.attach(MIMEText(message,'html'))
    text = msg.as_string()
    try: 
        smtp = smtplib.SMTP(retreiveSmtpData["host"], retreiveSmtpData["port"]) 
        smtp.starttls() 
        smtp.login(retreiveSmtpData["username"], retreiveSmtpData["password"])
        smtp.sendmail(retreiveSmtpData["username"], receiver,text) 

    #Terminating the session 
        smtp.quit() 
        print ("Email sent successfully!") 
    except Exception as ex: 
        print("Something went wrong....",ex)

def generate_code():
    numStr = ""
    for i in range(1,7):
        numStr += str(random.randint(0,9))
    return numStr       

def auth2FA(auth_type,code=None,email=None):
    FA2 = db002["2FA"]
    if auth_type == "get":
        fa2Info = FA2.find_one({"code":code,"email":email})
        if fa2Info is None:
            return False,  (jsonify({"message":"Double authentication code is incorrect", "status": "failed"}), 400)
        else:
            data = dict(fa2Info)
            if data["exp_date"]<datetime.utcnow():
                return False, (jsonify({"message":"Double authentication code is exipred", "status": "failed"}), 400)
            return True, 200
        
    if auth_type == "post":
        creation_date_time = datetime.utcnow()
        expiration_date_time = creation_date_time + timedelta(minutes=5)
        fa2Info = FA2.insert_one({"code":code,"email":email,"exp_date":expiration_date_time})
    
def passwdKey(password):
    hashalgo='sha256'
    salt='dsfsf!dAs'
    return hashalgo+"{"+hashlib.pbkdf2_hmac(hashalgo, bytes(password.encode('utf-8')), bytes(salt.encode('utf-8')), 100000).hex()+"}"

# def policy(password):
#     pwd = db002["pwd_policy"]
#     pwd_details = pwd.find_one({"name":"policy_details"})
#     strength = pwd_details["strength"]
#     strength_details = strength.split(",")
#     for i in strength_details:
#         if not re.search(i, password):
#             return False
#     return True if (len(password) > pwd_details["length"]) else False

def policy(password):
    policy_password = PasswordPolicy.from_names(
        length=8,  # min length: 8
        uppercase=1,  # need min. 2 uppercase letters
        numbers=1,  # need min. 2 digits
        special=1,  # need min. 2 special characters
        # nonletters=2,  # need min. 2 non-letter characters (digits, specials, anything)
    )
    result = policy_password.test(password)
    if len(result) == 0:
        return True, result
    return False, result

def validMail(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(re.search('^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', email)):   
        return True  
    else:
        if(re.fullmatch(regex, email)):
            return True
        return False 

def change_pass_after_time(app_id):
    ACCOUNT = db002["account"]
    result = ACCOUNT.find({"app_id": app_id, "is_expired": False})
    if result:
        for i in result:
            creation_date_time = i["date"]
            today_date_time = datetime.now()
            if today_date_time > creation_date_time + timedelta(days=password_expiration):
                ACCOUNT.find_one_and_update({'_id': i["_id"]}, {"$set": {"is_expired": True}},upsert=True)
    return None

def run_dag(taskid):
    try:
        me = creds.find_one({'type': 'airflow'})
        URL = me["url"] + "/api/v1/dags/launch_dag/dagRuns"
        data = "{\"conf\": {\"taskid\":\""+taskid+"\"}, \"dag_run_id\": \""+"airflow_"+taskid + str(random.random()) +"\" }"
        headers = {'Content-Type': 'application/json', 'accept': 'application/json' }
        results = requests.post(URL, data, auth=(me["value"]["username"], me["value"]["password"]), headers=headers)
        if results.status_code == 200:
            return "ok", 200
        else: return "something went wrong", results.status_code
    except Exception as err:
        return err

def fetchSons(mo, unsorted):
    for obj in unsorted:
        if obj['info']['managerID'] == mo['info']['uid']:
            mo['fils'].append(obj)
            fetchSons(obj, unsorted)

def isErrorKey(data, key):
    try:
        data[key]
        return True
    except KeyError:
        return False