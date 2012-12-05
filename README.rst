==============
CMFKerberosSso
==============

CMFKerberosSso will automatically authenticate in a CMF / Plone site an user who
already authenticated in a Kerberos service. Other users will need to
authenticate with usual CMF / Plone forms.

Requirements
============

- Plone 2.0.x or 2.1.x
- LDAPUserFolder

Installation
============

We assume that users can actually authenticate against an LDAP source through a
well configured LDAPUserFolder.

We assume that the front server (Apache, Nginx, ...) is configured such it
provides the user id in the X_REMOTE_USER HTTP header. (Todo : provide a sample
Apache configuration excerpt, and pointers)

Drop or symlink the ``CMFKerberosSso`` folder in the ``Products`` directory of
your Plone software stack. Restart your Zope instance or ZEO cluster.

In ZMI, and for each CMF / Plone site, remove the ``cookie_authentication``
object (a standard CMFCOre.CookieCrumbler object), and add a **Kerberos Cookie
Crumbler** object with the same name: ``cookie_authentication``.

You may go to its "Properties" tab to tweak its features according to your site
but the default setup is fine with a stock Plone site.

Potential conflicts
===================

Do **not** install ``CMFNtmlSso`` in the same Zope instance or ZEO cluster: both
override the same LDAPUserFolder method. So one of both will not work as
expected.

Todo
====

* Configurable HTTP header name (actually, X_REMOTE_USER is hardcoded)
* Configurable switch to extract the reak user id from HTTP header
* More documentation with Apache config
* Code cleanup (pep8, ...)
* Unit and functional tests

Credits
=======

Based on ideas from CMFNtlmSso by Nuxeo

* `Gilles Lenfant <gilles.lenfant@alterway.fr>`_
* `Aïssam Rehim <aissam.rehim@alterway.fr>`_
* `Alter Way <http://www.alterway.fr>`_
