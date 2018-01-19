import kerberos
from functools import wraps
from socket import gethostname
from flask import Response
from flask import make_response
from flask import request
from flask import session
from os import environ
from base64 import b64decode
import inspect
import ldap
import ldap.sasl
from Crypto.Cipher import AES
from base64 import b64decode, b64encode

_SERVICE_NAME = None
_logger = None
_cfg = None


def init_multiauth(app, servicetype='HTTP', hostname=gethostname()):
    """
    Configure the GSSAPI service name, and validate the principal in the kerberos keytab.

    @param app: a flask application
    @param servicetype: GSSAPI service type
    @param hostname: hostname service is running on
    """
    global _SERVICE_NAME
    _SERVICE_NAME = "{0}@{1}".format(servicetype, hostname)

    global _logger
    _logger = app.logger

    global _cfg
    _cfg = app.config

    if "KRB5_KTNAME" not in environ:
        _logger.warn("Please set KRB5_KTNAME to your fully quailified KRB5 ketab file name")
        return

    try:
        principal = kerberos.getServerPrincipalDetails(servicetype, hostname)
        app.logger.warn("flask_multiauth: server is %s" % principal)
    except kerberos.KrbError as exc:
        _logger.warn("flask_multiauth: %s" % exc.message[0])


def _unauthorized():
    """
    Default unathorized function
    """

    return Response("Unauthorized", 401, {'WWW-Authenticate': 'Negotiate'})


def _forbidden():
    """
    Default forbidden function
    """

    return Response("Forbidden", 403)


def _kerberos_auth(token):
    """
    Performs GSSAPI Negotiate Authentication

    Returns the retrun code and state so that token and user principle can be retrieved.

    @param token: GSSAPI Authentication Token
    @returns gssapi return and state
    @rtype: int or None, PyCObject
    """

    state = None
    rc = None
    try:
        rc, state = kerberos.authGSSServerInit(_SERVICE_NAME)
        if rc != kerberos.AUTH_GSS_COMPLETE:
            return None, state
        rc = kerberos.authGSSServerStep(state, token)
        if rc == kerberos.AUTH_GSS_COMPLETE:
            return rc, state
        elif rc == kerberos.AUTH_GSS_CONTINUE:
            return kerberos.AUTH_GSS_CONTINUE, state
        else:
            return None, state
    except kerberos.GSSError:
        return None, state
    finally:
        if state:
            kerberos.authGSSServerClean(state)


def _ldap_auth(kerb_user=None):
    """
    Performs LDAP Authentication and Group Membership Check

    If Keberos Authentication was successfull this function is used for the additional Group Membership Check.
    If Kerberos Authentication fails and a Basic Auth Header is preasent in the Request this function is called to
    to Authenticate using LDAP and additionally Check for Group Membership.
    Note: LDAP Groups are defined in the configuration file. (config.py)

    :param kerb_user: Will be None if doing complete Basic Auth will contain users principle if just checking Group
                      membership.
    :type user principle: str
    :returns None if auth failed and users principle if successfull
    :rtype: str or None
    """

    password = None
    username = None
    if kerb_user:
        username = kerb_user.split('@', 1)[0]
    elif ("HTTP_AUTHORIZATION" in request.headers.environ and "Basic" in request.environ["HTTP_AUTHORIZATION"]) or \
            "BASIC_AUTH" in session:
        if "BASIC_AUTH" in session:
            auth = session["BASIC_AUTH"].split(' ', 1)
        else:
            auth = request.headers.environ["HTTP_AUTHORIZATION"].split(' ', 1)
        try:
            username, password = b64decode((auth[1])).split(":")
        except Exception as ex:
            _logger.warn("Bad Request: Basic Auth header decode error")
            _logger.warn(ex)
            return None
    else:
        return None

    # Set ldap host
    ldap_connection = ldap.initialize(_cfg['LDAP_HOST'])
    # Set up cert, only required by the bind
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, _cfg['LDAP_CERT_PATH'])
    # set up query string. Used to verify user is in valid groups
    query = '(&(memberUid=' + username + ')(|' + _cfg['VALID_LDAP_GROUPS'] + "))"
    # Set up search base
    base = _cfg['LDAP_SEARCH_BASE']
    # Set up search scope
    search_scope = ldap.SCOPE_SUBTREE
    # None causes all to be returned
    retrieve_attributes = None

    authorized_user = None
    try:

        if not kerb_user:
            _logger.warn(": Could not authorize using kerberos, trying ldap")
            user = "uid=" + username + "," + _cfg['LDAP_BIND_BASE']
            ldap_connection.start_tls_s()
            if not ldap_connection.simple_bind_s(user, password):
                return None
            authorized_user = username

        if _cfg['VALID_LDAP_GROUPS'] != "()":
            # Search ldap to verify that user is in one of the defined valid groups
            ldap_result_id = ldap_connection.search(base, search_scope, query, retrieve_attributes)
            rtype, rdata = ldap_connection.result(ldap_result_id, 1)
            if rdata:
                authorized_user = username
            else:
                func = inspect.stack()[0][3]
                _logger.warn("{0} - Bad Request, could not verify users credentials - user not in group ".format(func))
                authorized_user = None
    except Exception as ex:
        func = inspect.stack()[0][3]
        _logger.warn("{0} - Bad Request, could not verifying users credentials ".format(func))
        _logger.warn(ex.message)
        authorized_user = None
    if authorized_user:
        return authorized_user
    else:
        func = inspect.stack()[0][3]
        _logger.warn("{0} - Bad Request, could not verifying users credentials ".format(func))
        return None


def authenticate(unauthorized=_unauthorized, forbidden=_forbidden):
    """
    The decorated view function will only be called if user is successfully authenticated with Kerberos or Basic Auth
    , as long as a Basic Auth header is present. Both valid Kerberos authentication or Basic Auth authenticated users
    will also be required to be a member of the defined ldap group.
    The decorated view function will have the authenticated users principal passed to it as its first argument.

    @param unauthorized: optional funcion to handle unauthorized
    @param forbidden: optional funcion to handle forbidden
    @returns: decorated function, unauthorized or forbidden
    """

    def decorator(func):
        @wraps(func)
        def inner(*args, **kwargs):

            if "LOGGED_IN_USER" in session:
                cipher = AES.new(_cfg["K"])
                user = cipher.decrypt(b64decode(session["LOGGED_IN_USER"]))
                user = user.rstrip()
                return func(user, *args, **kwargs)

            authorized_user = None
            header = request.headers.get("Authorization")
            if header and ("Negotiate" in header):
                token = ''.join(header.split()[1:])
                rc, state = _kerberos_auth(token)
                if rc == kerberos.AUTH_GSS_COMPLETE:
                    kerberos_token = kerberos.authGSSServerResponse(state)
                    authorized_user = _ldap_auth(kerberos.authGSSServerUserName(state))
                    if not authorized_user:
                        return unauthorized()
                    enc_user = "{:<16}".format(authorized_user)
                    cipher = AES.new(_cfg["K"])
                    crypt_user = b64encode(cipher.encrypt(enc_user))
                    response = func(authorized_user, *args, **kwargs)
                    response = make_response(response)
                    session["LOGGED_IN_USER"] = crypt_user
                    if kerberos_token is not None:
                        response.headers['WWW-Authenticate'] = ' '.join(['negotiate', kerberos_token])
                    return response
                elif rc != kerberos.AUTH_GSS_CONTINUE:
                    return forbidden()
            elif (header and "Basic" in header) or ("BASIC_AUTH" in session and "Basic" in session["BASIC_AUTH"]):
                usr = _ldap_auth(None)
                if not usr:
                    return unauthorized()
                enc_user = "{:<16}".format(usr)
                cipher = AES.new(_cfg["K"])
                crypt_user = b64encode(cipher.encrypt(enc_user))
                session["LOGGED_IN_USER"] = crypt_user
                return func(usr, *args, **kwargs)
            else:
                return unauthorized()
        return inner
    return decorator


def logout(function):
    '''
    Sets state to logged out by removing variables indicating a logged in state
    :param function: flask view function
    :type function: function
    :returns: decorated function
    :rtype: function
    '''
    @wraps(function)
    def logout_func(*args, **kwargs):

        if "LOGGED_IN_USER" in session:
            session.pop("LOGGED_IN_USER", None)
        if "BASIC_AUTH" in session:
            session.pop("BASIC_AUTH")
        return function()
    return logout_func
