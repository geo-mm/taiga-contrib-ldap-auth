# Copyright (C) 2014 Andrey Antukh <niwi@niwi.be>
# Copyright (C) 2014 Jesús Espino <jespinog@gmail.com>
# Copyright (C) 2014 David Barragán <bameda@dbarragan.com>
# Copyright (C) 2015 Ensky Lin <enskylin@gmail.com>
# Copyright (C) 2018 Joseph Yang <geo.mm.yahoo@gmail.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ldap3 import Server, Connection, SIMPLE, ANONYMOUS, SYNC, SIMPLE, SYNC, ASYNC, SUBTREE, NONE

from django.conf import settings
from taiga.base.connectors.exceptions import ConnectorBaseException


class LDAPLoginError(ConnectorBaseException):
    pass


SERVER = getattr(settings, "LDAP_SERVER", "")
PORT = getattr(settings, "LDAP_PORT", "")

SEARCH_BASE = getattr(settings, "LDAP_SEARCH_BASE", "")
SEARCH_PROPERTY = getattr(settings, "LDAP_SEARCH_PROPERTY", "")
SEARCH_SUFFIX = getattr(settings, "LDAP_SEARCH_SUFFIX", "")
SEARCH_FILTER = getattr(settings, "LDAP_SEARCH_FILTER", "")
BIND_DN = getattr(settings, "LDAP_BIND_DN", "")
BIND_PASSWORD = getattr(settings, "LDAP_BIND_PASSWORD", "")
SEARCH_CUSTOM_FILTER = getattr(settings, "LDAP_SEARCH_CUSTOM_FILTER", None)

USERNAME_PROPERTY = getattr(settings, "LDAP_USERNAME_PROPERTY", "")
ROLE_PROPERTY = getattr(settings, "LDAP_ROLE_PROPERTY", "ou")
EMAIL_PROPERTY = getattr(settings, "LDAP_EMAIL_PROPERTY", "")
FULL_NAME_PROPERTY = getattr(settings, "LDAP_FULL_NAME_PROPERTY", "")

def getAttrByName(resp, prop):
    try:
       ret = resp.get('raw_attributes').get(prop)[0].decode('utf-8')
       return ret
    except Exception as e:
       return ''

def emptyStr(string):
    return string is None or string == ''

def login(username: str, password: str) -> tuple:
    try:
        # define an unsecure LDAP server, requesting info on DSE and schema
        server = Server(SERVER, port = PORT, get_info = NONE, use_ssl = SERVER.lower().startswith("ldaps://"))

        (_user, _pass, _auth) = (None, None, ANONYMOUS) if emptyStr(BIND_DN) else (BIND_DN, BIND_PASSWORD, SIMPLE)

        c = Connection(server, \
                       auto_bind = True, \
                       client_strategy = SYNC, \
                       user=_user, \
                       password=_pass, \
                       authentication=_auth, \
                       check_names=True)

    except Exception as e:
        error = "Error connecting to LDAP server: %s" % e
        raise LDAPLoginError({"error_message": error})

    try:
        #if not emptyStr(SEARCH_SUFFIX):
        #    search_filter = '(%s=%s)' % (SEARCH_PROPERTY, username + SEARCH_SUFFIX)
        #else:
        #    search_filter = '(%s=%s)' % (SEARCH_PROPERTY, username)

        search_filter = '(%s=%s)' % (SEARCH_PROPERTY, username + SEARCH_SUFFIX if not emptyStr(SEARCH_SUFFIX) else '')

        if SEARCH_FILTER:
            search_filter = '(&%s(%s))' % (search_filter, SEARCH_FILTER)
        if not emptyStr(SEARCH_CUSTOM_FILTER):
            search_filter = SEARCH_CUSTOM_FILTER.format(username=username)

        c.search(search_base = SEARCH_BASE,
                 search_filter = search_filter,
                 search_scope = SUBTREE,
                 attributes = [USERNAME_PROPERTY, ROLE_PROPERTY, EMAIL_PROPERTY, FULL_NAME_PROPERTY],
                 paged_size = 5)

        if len(c.response) > 0:
            resp = c.response
            dn = resp.get('dn')
            user_name = getAttrByName(resp, USERNAME_PROPERTY)
            user_name = username if emptyStr(user_name) else user_name
            user_email = getAttrByName(resp, EMAIL_PROPERTY)
            full_name = getAttrByName(resp, FULL_NAME_PROPERTY)
            is_admin = (getAttrByName(resp, ROLE_PROPERTY) == 'admin')
            user_conn = Connection(server, \
                                   auto_bind = True, \
                                   client_strategy = SYNC, \
                                   user = dn, \
                                   password = password, \
                                   authentication = SIMPLE, \
                                   check_names = True)

            return (user_name, user_email, full_name, is_admin)

        raise LDAPLoginError({"error_message": "Username or password incorrect"})

    except Exception as e:
        error = "LDAP account or password incorrect: %s" % e
        raise LDAPLoginError({"error_message": error})
