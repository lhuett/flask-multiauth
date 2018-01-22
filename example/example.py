import logging

from flask import Response, session
from base64 import b64encode
from flask import jsonify, Flask, render_template, request, redirect, url_for
from os import environ
from flask_multiauth import authenticate, init_multiauth, logout
import config_example
import socket

authex = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger("TEST")


init_multiauth(authex)


def _unauthorized():

    error = "Please make sure to run the 'kinit' command or enter user id and password and that you are in " \
            "the proper ldap group"

    session["next"] = request.endpoint
    return Response(render_template('login.html', error=error), 401, {'WWW-Authenticate': 'Negotiate'})


def _forbidden():
    error = "Forbidden - Invalid Kerberos credentials.\n"
    return Response(error, 403)


@authex.route('/example/ldap_login/', methods=['GET', 'POST'])
def ldap_login():


    basic_auth = b64encode("{0}:{1}".format(request.form["username"],request.form["password"]))

    session["BASIC_AUTH"] = "Basic {0}".format(basic_auth)

    return redirect(url_for(session["next"], _external=True, _scheme='HTTP'))


@authex.route('/example/auth/', methods=['GET'])
@authenticate(unauthorized=_unauthorized, forbidden=_forbidden)
def auth(user):


    if user:
        return jsonify({"status": "Success - auth"}, {"user": user})
    return jsonify({"status": "Failed - auth"}, {"message": "No user returned from authentication"})


@authex.route('/example/newone/', methods=['GET', 'POST'])
@authenticate(unauthorized=_unauthorized, forbidden=_forbidden)
def newone(user = None):

    if user:
        return jsonify({"status": "Success - newone"}, {"user": user})
    return jsonify({"status": "Failed - newone"}, {"message": "No user returned from authentication"})


@authex.route('/example/logout/', methods=['GET'])
@logout
def logout():

    return jsonify({"status": "Logged Out"})


# Main
if __name__ == "__main__":

    if "LDAP_CONFIG" not in environ:
        logger.warn("Please set LDAP_CONFIG to your fully quailified ldap configuration file name")
        exit(1)
    try:
        authex.config.from_envvar("LDAP_CONFIG")
    except Exception as ex:
        logger.error("Could not load LDAP config from file - {0}".format(environ.get("LDAP_CONFIG")))
        exit(1)

    environ["KRB5_KTNAME"] = authex.config["KRB5_KTNAME"]
    authex.secret_key = authex.config["SESSION_SECRET_KEY"]

    authex.run(host='0.0.0.0', port=5006, debug=True)


