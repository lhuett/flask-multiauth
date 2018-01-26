import platform
import os


#LDAP Config
GROUP_AUTH = False
VALID_LDAP_GROUPS = '(cn=)'
LDAP_SEARCH_BASE = 'ou=,dc=,dc='
LDAP_BIND_BASE = 'ou=,dc=,dc='
LDAP_HOST = 'ldap://<ldap_server>'
LDAP_CERT_PATH = '/etc/pki/tls/certs/some_cert.crt'


KRB5_KTNAME = "<path to KRB5 Keyutab file>"

LDAP_GROUP_SEARCH_BASE = "dc=,dc=com"

SESSION_TYPE = "filesystem"

K = "<some secret phrase>"

SESSION_SECRET_KEY = "<some secret phrase>"