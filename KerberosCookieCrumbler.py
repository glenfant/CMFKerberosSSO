# -*- coding: utf-8 -*-
# Copyright (c) 2012 Alter Way <http://www.alterway.fr>
# Author: Gilles Lenfant <gilles.lenfant@alterway.fr>

from base64 import encodestring
from urllib import quote, unquote
from DateTime import DateTime
from types import ListType
from Globals import InitializeClass
from AccessControl import ClassSecurityInfo
from ZPublisher.HTTPRequest import HTTPRequest
from Products.CMFCore import CookieCrumbler
from Products.CMFCore.CookieCrumbler import ATTEMPT_NONE, ATTEMPT_RESUME, \
     CookieCrumblerDisabled, ATTEMPT_LOGIN
from zLOG import LOG, DEBUG, ERROR


class KerberosCookieCrumbler(CookieCrumbler.CookieCrumbler):
    meta_type = 'Kerberos Cookie Crumbler'
    title = 'Kerberos Cookie Crumbler'

    security = ClassSecurityInfo()

    security.declarePrivate('modifyRequest')
    def modifyRequest(self, request, response):
        """Overrrides CMFCore.CookieCrumbler
        """
        # Check we are handling a correct HTTP request
        if request.__class__ is not HTTPRequest:
            raise CookieCrumblerDisabled

        if (request['REQUEST_METHOD'] not in ('HEAD', 'GET', 'PUT', 'POST')
            and not request.has_key(self.auth_cookie)):
            raise CookieCrumblerDisabled

        if request.environ.has_key('WEBDAV_SOURCE_PORT'):
            raise CookieCrumblerDisabled

        username = getattr(request, 'kerberos_authenticated_user', None)
        if username:
            pass

        # We check if we have the Kerberos header
        elif request.get('HTTP_X_REMOTE_USER'):
            username = request.get('HTTP_X_REMOTE_USER')
            # Attention, remove potential "@domain.tld"
            username = username.rsplit('@', 1)[0]
            setattr(request, 'kerberos_authenticated_user', username)

        # GL : A priori ceci ne s'applique pas pour Kerberos
        #elif request.get('QUERY_STRING') != '':
        elif False:
            qs = request.get('QUERY_STRING')
            if '&amp;' in qs:
                split_query = qs.split('&amp;')
                for parameter in split_query:
                    if '&' in parameter:
                        split_query.remove(parameter)
                        for e in parameter.split('&'):
                            split_query.append(e)
            else:
                split_query = qs.split('&')

            for parameter in split_query:
                if parameter.startswith('ntlm_remote_user='):
                    ## XXX len('ntlm_remote_user=') = 17
                    username = parameter[17:]
                    split_query.remove(parameter)

            setattr(request, 'kerberos_authenticated_user', username)
            request.environ['QUERY_STRING'] = '&amp;'.join(split_query)
            # cleaning form, at least
            if request.form.get('ntlm_remote_user'):
                del request.form['ntlm_remote_user']

        else:
            username = False
            setattr(request, 'kerberos_authenticated_user', None)

        if isinstance(username, ListType):
            username = username[0]

        # GL : This is a copy of what's remaining in CookieCrumbler.modifyRequest
        ## condition for: username is not None and username != ''
        if username:
            user = self.acl_users.getUser(username)
            if user is None:
                # The user in the certificate does not exist
                LOG('Kerberos Cookie Crumbler', ERROR, "User '%s' did not exist\n" % username)
                raise CookieCrumblerDisabled

            ##user._getPassword return nothing usable from LDAPUserGroupsFolder
            #password = user._getPassword()
            #ac = encodestring('%s:%s' % (username, password))
            ac = encodestring('%s:%s' % (username, '__'+username+'__'))
            request._auth = 'Basic %s' % ac
            request._cookie_auth = 1
            response._auth = 1
            return ATTEMPT_RESUME
        elif request._auth and not getattr(request, '_cookie_auth', 0):
            # Using basic auth.
            raise CookieCrumblerDisabled
        else:
            if request.has_key(self.pw_cookie) and request.has_key(self.name_cookie):
                # Attempt to log in and set cookies.
                name = request[self.name_cookie]
                pw = request[self.pw_cookie]
                ac = encodestring('%s:%s' % (name, pw))
                request._auth = 'Basic %s' % ac
                request._cookie_auth = 1
                response._auth = 1
                if request.get(self.persist_cookie, 0):
                    # Persist the user name (but not the pw or session)
                    expires = (DateTime() + 365).toZone('GMT').rfc822()
                    response.setCookie(self.name_cookie, name, path='/',
                                   expires=expires)
                else:
                    # Expire the user name
                    response.expireCookie(self.name_cookie, path='/')
                method = self.getCookieMethod( 'setAuthCookie'
                                             , self.defaultSetAuthCookie )
                method(response, self.auth_cookie, quote(ac))
                self.delRequestVar(request, self.name_cookie)
                self.delRequestVar(request, self.pw_cookie)
                return ATTEMPT_LOGIN
            elif request.has_key(self.auth_cookie):
                # Copy __ac to the auth header.
                ac = unquote(request[self.auth_cookie])
                request._auth = 'Basic %s' % ac
                request._cookie_auth = 1
                response._auth = 1
                self.delRequestVar(request, self.auth_cookie)
                return ATTEMPT_RESUME
            return ATTEMPT_NONE


InitializeClass(KerberosCookieCrumbler)

manage_addCCForm = CookieCrumbler.manage_addCCForm

def manage_addCC(self, id, REQUEST=None):
    """ interface to add a NTML Cookie Crumbler """
    ob = KerberosCookieCrumbler()
    ob.id = id
    self._setObject(id, ob)
    if REQUEST is not None:
        return self.manage_main(self, REQUEST)
    return id
