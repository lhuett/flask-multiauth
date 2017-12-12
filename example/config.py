import platform

import os


#LDAP Config
VALID_LDAP_GROUPS = '(cn=rhi_data)'
LDAP_SEARCH_BASE = 'ou=groups,dc=redhat,dc=com'
LDAP_BIND_BASE = 'ou=Users,dc=redhat,dc=com'
LDAP_HOST = 'ldap://ldap.corp.redhat.com'
LDAP_CERT_PATH = '/etc/pki/tls/certs/RH-IT-Root-CA.crt'


CERT_BUNDLE = '/etc/pki/tls/certs/ca-bundle.crt'

KRB5_KEYTAB='/home/lhuett/HTTP-ceehadoop1.gsslab.rdu2.redhat.com.keytab'
