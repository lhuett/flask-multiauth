import logging

from flask import Response
from base64 import b64encode
from flask import jsonify, Flask, render_template, request, redirect, url_for
from os import environ
from flask_multiauth import authenticate, init_multiauth
import config_example as cfg
import socket


authex = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger("TEST")

init_multiauth(authex)

def _unauthorized():


    error = "Please make sure to run the 'kinit' command or enter user id and password and that you are in " \
            "the proper ldap group"

    return Response("User not Authorized", 401, {'WWW-Authenticate': 'Negotiate'})


def _forbidden():
    error = "Forbidden - Invalid Kerberos credentials.\n"
    return Response(error, 403)


@authex.route('/example/ldap_login/', methods=['GET', 'POST'])
def ldap_login():


    basic_auth = b64encode("{0}:{1}".format(request.form["username"],request.form["password"]))

    request.environ.update({"HTTP_AUTHORIZATION": "Basic {0}".format(basic_auth)})

    return example()


@authex.route('/example/auth/', methods=['GET'])
@authenticate(unauthorized=_unauthorized, forbidden=_forbidden)
def example(user):

    if user:
        return jsonify({"status": "Success"}, {"user": user})
    print "hmmm"


# Main
if __name__ == "__main__":

    if "LDAP_CONFIG" not in environ:
        logger.warn("Please set LDAP_CONFIG to your fully quailified ldap configuration file name")
    else:
        try:
            authex.config.from_envvar("LDAP_CONFIG")
        except Exception as ex:
            logger.error("Could not load LDAP config from file - {0}".format(environ.get("LDAP_CONFIG")))
        else:
            authex.run(host='0.0.0.0', port=5006, debug=True)
