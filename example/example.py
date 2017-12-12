import logging

from flask import Response
from flask import jsonify, Flask

import config as cfg
from flask_multiauth import authenticate, init_multiauth

testauth = Flask(__name__)
testauth.config.from_object(cfg)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger("TEST")

init_multiauth(testauth, "HTTP", "ceehadoop1.gsslab.rdu2.redhat.com")


def _unauthorized():

    error = "Unauthorized  - Could not authorize via Kerberos, please run the 'kinit' from the command line " \
            "and retry, or supply user credentials in the Basic Auth header.\n"
    return Response(error, 401, {'WWW-Authenticate': 'Negotiate'})


def _forbidden():
    error = "Forbidden - Invalid Kerberos credentials.\n"
    return Response(error, 403)


@testauth.route('/example/auth/', methods=['GET'])
@authenticate(unauthorized=_unauthorized, forbidden=_forbidden)
def example(user):

    return jsonify({"status": "Success"}, {"user": user})


# Main
if __name__ == "__main__":

    testauth.run(host='0.0.0.0', port=5006, debug=True)
