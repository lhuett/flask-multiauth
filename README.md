# flask-multiauth
Flask-MultiAuth allows the developer to simply decorate a flask view, that is in need of authentication, to get both
Kerberos or LDAP authentication.

## Configuration
You will need to configure flask with the following parameters for ldap Support

- VALID_LDAP_GROUPS = '(cn=<common name for group>)'     (Set to () if no group checking to be done)
    - Example: VALID_LDAP_GROUPS = '(cn=my_ldap_group)'
- LDAP_SEARCH_BASE = 'ou=<orginizationUnitName>,dc=<domainComponent>,dc=<domainComponent>'
    - Example: LDAP_SEARCH_BASE = 'ou=groups,dc=google,dc=com'
- LDAP_BIND_BASE = 'ou=organizationalUnit,dc=domainComponent,dc=domainComponent'
    - Example: LDAP_BIND_BASE = 'ou=Users,dc=google,dc=com'
- LDAP_HOST = 'ldap:<ldap_server_name>'
    - Example: 'ldap://my.ldap.server.com'
- LDAP_CERT_PATH = '<fully_qualified_cert_file_name>'
    - Example: LDAP_CERT_PATH = '/etc/pki/tls/certs/my-ca-cert-file.crt'
    
## Requirements