# -*- coding: utf-8 -*-
# Copyright (c) 2012 Alter Way <http://www.alterway.fr>
# Author: Gilles Lenfant <gilles.lenfant@alterway.fr>

try:
    from Products.LDAPUserFolder.LDAPUserFolder import LDAPUserFolder
    HAVE_LDAPUF = True
except ImportError:
    HAVE_LDAPUF = False

from AccessControl.User import domainSpecMatch

#security.declarePrivate('authenticate')
def Kerberos_authenticate(self, name, password, request):
    """Authenticate a user from a name and password.

    (Called by validate).

    Returns the user object, or None.
    """
    super = self._emergency_user
    kerberos_user = getattr(request, 'kerberos_authenticated_user', None)

    if not name:
        return None

    if super and name == super.getUserName():
        user = super
    else:
        if kerberos_user is not None:
            user = self.getUserById(name)
        else:
            user = self.getUser(name, password)

    if user is not None:
        domains = user.getDomains()
        if domains:
            return (domainSpecMatch(domains, request) and user) or None

    return user

if HAVE_LDAPUF:
    LDAPUserFolder.authenticate = Kerberos_authenticate
