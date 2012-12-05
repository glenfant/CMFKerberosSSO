# -*- coding: utf-8 -*-
# Copyright (c) 2012 Alter Way <http://www.alterway.fr>
# Author: Gilles Lenfant <gilles.lenfant@alterway.fr>

# Add LDAPUserFolder patch for Kerberos authentication
import LDAPUserFolderPatch

# Add Kerberos Cookie Crumbler patch for SSO
import KerberosCookieCrumbler

def initialize(registrar):
    registrar.registerClass(
        KerberosCookieCrumbler.KerberosCookieCrumbler,
        constructors=(
            KerberosCookieCrumbler.manage_addCCForm,
            KerberosCookieCrumbler.manage_addCC,
            ),
        #icon = 'cookie.gif'
        )
