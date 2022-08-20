import argparse,pymongo
from flask_cors import CORS
import os
from flask import Flask, jsonify
from flask_swagger_ui import get_swaggerui_blueprint
from routes import request_api
from flask_pymongo import PyMongo

from modules.ldapauth import LDAP_REQUEST
from modules.applications import APP_REQU
from modules.secret import SECRET_REQU
from modules.password import PASSWORD_REQUEST
from modules.organigram import ORGANIGRAM_REQUEST
from waitress import serve
app = Flask(__name__)
# CORS(app, origins=["http://10.0.0.76:8080/login","http://10.0.0.76:8080/register"])
app.config["DEBUG"] = True
# CORS(app, origins=["http://azumarillapi.axe-tag.com/"])
SWAGGER_URL = '/swagger/'
API_URL2 = "/api/v1/"
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Seans-Python-Flask-REST-Boilerplate"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)
app.register_blueprint(request_api.get_blueprint())
#
app.register_blueprint(LDAP_REQUEST, url_prefix=API_URL2+"auth")
app.register_blueprint(APP_REQU, url_prefix=API_URL2+"application")
app.register_blueprint(SECRET_REQU, url_prefix=API_URL2+"secret")
app.register_blueprint(PASSWORD_REQUEST, url_prefix=API_URL2+"password")
app.register_blueprint(ORGANIGRAM_REQUEST, url_prefix=API_URL2+"organigram")


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(
        description="Seans-Python-Flask-REST-Boilerplate")

    PARSER.add_argument('--debug', action='store_true',
                        help="Use flask debug/dev mode with file change reloading")
    ARGS = PARSER.parse_args()

    PORT = int(os.environ.get('PORT', 5001))

    if ARGS.debug:
        print("Running in debug mode")
        app.run(host='0.0.0.0', port=PORT, debug=True) #, ssl_context=('cert.pem', 'priv_key.pem')
    else:
        # serve(app, host="0.0.0.0", port=PORT)
        app.run(host='0.0.0.0', port=PORT, debug=False, ssl_context=('adhoc')) #
