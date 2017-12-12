import logging

from flask import Response
from flask import jsonify, Flask
from os import environ
from flask_multiauth import authenticate, init_multiauth

authex = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger("TEST")

init_multiauth(authex, "HTTP", "ceehadoop1.gsslab.rdu2.redhat.com")


def _unauthorized():

    error = "Unauthorized  - Could not authorize via Kerberos, please run the 'kinit' from the command line " \
            "and retry, or supply user credentials in the Basic Auth header.\n"
    return Response(error, 401, {'WWW-Authenticate': 'Negotiate'})


def _forbidden():
    error = "Forbidden - Invalid Kerberos credentials.\n"
    return Response(error, 403)


@authex.route('/example/auth/', methods=['GET'])
@authenticate(unauthorized=_unauthorized, forbidden=_forbidden)
def example(user):

    return jsonify({"status": "Success"}, {"user": user})


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
