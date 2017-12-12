# Flask-MultiAuth
Flask-MultiAuth allows the developer to simply decorate a flask view, that is in need of authentication, to get both
Kerberos or LDAP authentication.

## How To Install

$ pip install --upgrade git+git://github.com/lhuett/flask-multiauth.git

## Configuration:
You will need to configure you flask app with the following parameters for ldap Support

- VALID_LDAP_GROUPS = '(cn=common_name_for_group)'     (Set to () if no group checking to be done)
    - Example: VALID_LDAP_GROUPS = '(cn=my_ldap_group)'
- LDAP_SEARCH_BASE = 'ou=orginizationUnitName,dc=domainComponent,dc=domainComponent'
    - Example: LDAP_SEARCH_BASE = 'ou=groups,dc=somedomain,dc=com'
- LDAP_BIND_BASE = 'ou=organizationalUnit,dc=domainComponent,dc=domainComponent'
    - Example: LDAP_BIND_BASE = 'ou=Users,dc=somedomain,dc=com'
- LDAP_HOST = 'ldap:ldap_server_name'
    - Example: 'ldap://my.ldap.server.com'
- LDAP_CERT_PATH = '<fully_qualified_cert_file_name>'
    - Example: LDAP_CERT_PATH = '/etc/pki/tls/certs/my-ca-cert-file.crt'
    
## Requirements:

#### Environment
- You must have a KRB5 keytab file for your service priciple on the server that you app will be 
running on.
- In order to use Basic Auth to authenticate with ldap you must be able to access the ldap 
service. You must also have acess to the ldap server information required to populate the 
configuration previously explained in this document. 

#### Environment Variables:
- KRB5_KTNAME - This should be set to the fully qualified name of you service principles keytab file

#### Simple Example
A very simple example is available in this [github project's](https://github.com/lhuett/flask-multiauth)
example directory 






