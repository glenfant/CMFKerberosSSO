# -*- coding: utf-8 -*-
# Copyright (c) 2012 Alter Way <http://www.alterway.fr>
# Author: Aissam REHIM <aissam.rehim@alterway.fr>


import base64
from cStringIO import StringIO
import sys
import unittest
import urllib

import Testing
from OFS.DTMLMethod import DTMLMethod
from OFS.Folder import Folder
from zExceptions.unauthorized import Unauthorized
from AccessControl.User import UserFolder
from AccessControl.SecurityManagement import noSecurityManager
from ZPublisher.HTTPRequest import HTTPRequest
from ZPublisher.HTTPResponse import HTTPResponse
from ZPublisher.BaseRequest import RequestContainer
from zExceptions import Redirect

from Products.CMFKerberosSSO.KerberosCookieCrumbler, \
     import KerberosCookieCrumbler, manage_addCC


def makerequest(root, stdout, stdin=None):
    # Customized version of Testing.makerequest.makerequest()
    resp = HTTPResponse(stdout=stdout)
    environ = {}
    environ['SERVER_NAME'] = 'example.com'
    environ['SERVER_PORT'] = '80'
    environ['REQUEST_METHOD'] = 'GET'
    if stdin is None:
        stdin = StringIO('')  # Empty input
    req = HTTPRequest(stdin, environ, resp)
    req['PARENTS'] = [root]
    return req


class CMFKerberosSSOTests (unittest.TestCase):

    def setUp(self):
        root = Folder()
        self.root = root
        root.isTopLevelPrincipiaApplicationObject = 1 
        root.getPhysicalPath = lambda: ()  # hack
        root._View_Permission = ('Anonymous',)

        users = UserFolder()
        users._setId('acl_users')
        users._doAddUser('gilles', 'pass-w', ('HeadMaster',), ())
        users._doAddUser('aissam', 'pass-w', ('Master',), ())
        root._setObject(users.id, users)

        cc = KerberosCookieCrumbler()
        cc.id = 'cookie_authentication'
        root._setObject(cc.id, cc)
        self.cc = getattr(root, cc.id)

        index = DTMLMethod()
        index.munge('This is the default view')
        index._setId('index_html')
        root._setObject(index.getId(), index)

        login = DTMLMethod()
        login.munge('Please log in first.')
        login._setId('login_form')
        root._setObject(login.getId(), login)

        protected = DTMLMethod()
        protected._View_Permission = ('Manager',)
        protected.munge('This is the protected view')
        protected._setId('protected')
        root._setObject(protected.getId(), protected)

        self.responseOut = StringIO()
        self.req = makerequest(root, self.responseOut)

        self.credentials = urllib.quote(
            base64.encodestring('gilles:pass-w').rstrip())


    def tearDown(self):
        self.req.close()
        noSecurityManager()


    def testNoCookies(self):
        # verify the kerberos crumbler doesn't break when no cookies are given
        self.req.traverse('/')
        self.assertEqual(self.req['AUTHENTICATED_USER'].getUserName(),
                         'Anonymous User')


    def testCookieLogin(self):
        # verify the user and auth cookie get set
        self.req.cookies['__ac_name'] = 'gilles'
        self.req.cookies['__ac_password'] = 'pass-w'
        self.req.traverse('/')

        self.assert_(self.req.has_key('AUTHENTICATED_USER'))
        self.assertEqual(self.req['AUTHENTICATED_USER'].getUserName(),
                         'gilles')
        resp = self.req.response
        self.assert_(resp.cookies.has_key('__ac'))
        self.assertEqual(resp.cookies['__ac']['value'],
                         self.credentials)
        self.assertEqual(resp.cookies['__ac']['path'], '/')


    def testCookieResume(self):
        # verify the kerberos crumbler continues the session
        self.req.cookies['__ac'] = self.credentials
        self.req.traverse('/')
        self.assert_(self.req.has_key('AUTHENTICATED_USER'))
        self.assertEqual(self.req['AUTHENTICATED_USER'].getUserName(),
                         'gilles')


    def testPasswordShredding(self):
        # verify the password is shredded before the app gets the request
        self.req.cookies['__ac_name'] = 'gilles'
        self.req.cookies['__ac_password'] = 'pass-w'
        self.assert_(self.req.has_key('__ac_password'))
        self.req.traverse('/')
        self.assert_(not self.req.has_key('__ac_password'))
        self.assert_(not self.req.has_key('__ac'))


    def testCredentialsNotRevealed(self):
        # verify the credentials are shredded before the app gets the request
        self.req.cookies['__ac'] = self.credentials
        self.assert_(self.req.has_key('__ac'))
        self.req.traverse('/')
        self.assert_(not self.req.has_key('__ac'))


    def testAutoLoginRedirection(self):
        # Redirect unauthorized anonymous users to the login page
        self.assertRaises(Redirect, self.req.traverse, '/protected')


    def testDisabledAutoLoginRedirection(self):
        # When disable_cookie_login__ is set, don't redirect.
        self.req['disable_cookie_login__'] = 1
        self.assertRaises(Unauthorized, self.req.traverse, '/protected')


    def testNoRedirectAfterAuthenticated(self):
        # Don't redirect already-authenticated users to the login page,
        # even when they try to access things they can't get.
        self.req.cookies['__ac'] = self.credentials
        self.assertRaises(Unauthorized, self.req.traverse, '/protected')


    def testRetryLogin(self):
        # After a failed login, CMFKerbersosSSO should give the user an
        # opportunity to try to log in again.
        self.req.cookies['__ac_name'] = 'aissam'
        self.req.cookies['__ac_password'] = 'pass-w'
        try:
            self.req.traverse('/protected')
        except Redirect, s:
            # Test passed
            if hasattr(s, 'args'):
                s = s.args[0]
            self.assert_(s.find('came_from=') >= 0)
            self.assert_(s.find('retry=1') >= 0)
            self.assert_(s.find('disable_cookie_login__=1') >= 0)
        else:
            self.fail('Did not redirect')


    def testLoginRestoresQueryString(self):
        # When redirecting include the submitted URL and the query string.
        self.req['PATH_INFO'] = '/protected'
        self.req['QUERY_STRING'] = 'a:int=1&x:string=y'
        try:
            self.req.traverse('/protected')
        except Redirect, s:
            if hasattr(s, 'args'):
                s = s.args[0]
            to_find = urllib.quote('/protected?' + self.req['QUERY_STRING'])
            self.assert_(s.find(to_find) >= 0, s)
        else:
            self.fail('Did not redirect')


    def testCacheHeaderAnonymous(self):
        # Should not set cache-control
        self.req.traverse('/')
        self.assertEqual(
            self.req.response.headers.get('cache-control', ''), '')


    def testCacheHeaderLoggingIn(self):
        # Should set cache-control
        self.req.cookies['__ac_name'] = 'gilles'
        self.req.cookies['__ac_password'] = 'pass-w'
        self.req.traverse('/')
        self.assertEqual(self.req.response['cache-control'], 'private')


    def testCacheHeaderAuthenticated(self):
        # Should set cache-control
        self.req.cookies['__ac'] = self.credentials
        self.req.traverse('/')
        self.assertEqual(self.req.response['cache-control'], 'private')


    def testCacheHeaderDisabled(self):
        # Should not set cache-control
        self.cc.cache_header_value = ''
        self.req.cookies['__ac'] = self.credentials
        self.req.traverse('/')
        self.assertEqual(
            self.req.response.headers.get('cache-control', ''), '')


    def testDisableLoginDoesNotPreventPasswordShredding(self):
        # Even if disable_cookie_login__ is set, read the cookies
        # anyway to avoid revealing the password to the app.
        # (disable_cookie_login__ does not mean disable cookie
        # authentication, it only means disable the automatic redirect
        # to the login page.)
        self.req.cookies['__ac_name'] = 'gilles'
        self.req.cookies['__ac_password'] = 'pass-w'
        self.req['disable_cookie_login__'] = 1
        self.req.traverse('/')
        self.assertEqual(self.req['AUTHENTICATED_USER'].getUserName(),
                         'gilles')
        # Here is the real test: the password should have been shredded.
        self.assert_(not self.req.has_key('__ac_password'))


    def testDisableLoginDoesNotPreventPasswordShredding2(self):
        self.req.cookies['__ac'] = self.credentials
        self.req['disable_cookie_login__'] = 1
        self.req.traverse('/')
        self.assertEqual(self.req['AUTHENTICATED_USER'].getUserName(),
                         'gilles')
        self.assert_(not self.req.has_key('__ac'))


    def testMidApplicationAutoLoginRedirection(self):
        # Redirect anonymous users to login page if Unauthorized
        # occurs in the middle of the app
        self.req.traverse('/')
        try:
            raise Unauthorized
        except:
            self.req.response.exception()
            self.assertEqual(self.req.response.status, 302)


    def testMidApplicationAuthenticationButUnauthorized(self):
        # Don't redirect already-authenticated users to the login page,
        # even when Unauthorized happens in the middle of the app.
        self.req.cookies['__ac'] = self.credentials
        self.req.traverse('/')
        try:
            raise Unauthorized
        except:
            self.req.response.exception()
            self.assertEqual(self.req.response.status, 401)


    def testRedirectOnUnauthorized(self):
        # Redirect already-authenticated users to the unauthorized
        # handler page if that's what the sysadmin really wants.
        self.root.cookie_authentication.unauth_page = 'login_form'
        self.req.cookies['__ac'] = self.credentials
        self.assertRaises(Redirect, self.req.traverse, '/protected')


    def testLoginRatherThanResume(self):
        # When the user presents both a session resume and new
        # credentials, choose the new credentials (so that it's
        # possible to log in without logging out)
        self.req.cookies['__ac_name'] = 'aissam'
        self.req.cookies['__ac_password'] = 'pass-w'
        self.req.cookies['__ac'] = self.credentials
        self.req.traverse('/')

        self.assert_(self.req.has_key('AUTHENTICATED_USER'))
        self.assertEqual(self.req['AUTHENTICATED_USER'].getUserName(),
                         'aissam')


    def testCreateForms(self):
        # Verify the factory creates the login forms.
        if CookieCrumbler.__module__.find('CMFCore') >= 0:
            # This test is disabled in CMFCore.
            return
        self.root._delObject('cookie_authentication')
        manage_addCC(self.root, 'login', create_forms=1)
        ids = self.root.login.objectIds()
        ids.sort()
        self.assertEqual(tuple(ids), (
            'index_html', 'logged_in', 'logged_out', 'login_form',
            'standard_login_footer', 'standard_login_header'))

def test_suite():
    return unittest.makeSuite(CMFKerberosSSOTests)

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
