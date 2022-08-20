from genericpath import exists
from flask import Flask, request,jsonify, Blueprint, json
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint
import requests 
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from flask_ldap3_login import LDAP3LoginManager

DOUBLE_AUTH = Blueprint("auth", __name__)
@DOUBLE_AUTH.route('/double_ath', methods=['POST'])
def double_auth():
    return ({"response":""})