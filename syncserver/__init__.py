# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import logging
from urlparse import urlparse, urlunparse

from pyramid.response import Response
from pyramid.events import NewRequest, subscriber

import mozsvc.config

from tokenserver.util import _JSONError

logger = logging.getLogger("syncserver")


## FIXME: should add Access-Control-Max-Age

class AccessControlMiddleware(object):

    def __init__(self, app, allow_origin, allow_methods, allow_headers=None,
                 expose_headers=None):
        self.app = app
        self.allow_origin = allow_origin
        if not isinstance(allow_methods, basestring):
            allow_methods = ', '.join(allow_methods)
        self.allow_methods = allow_methods
        if allow_headers and not isinstance(allow_headers, basestring):
            allow_headers = ', '.join(allow_headers)
        self.allow_headers = allow_headers
        if expose_headers and not isinstance(expose_headers, basestring):
            expose_headers = ', '.join(expose_headers)
        self.expose_headers = expose_headers
        self.base_headers = [
            ('Access-Control-Allow-Methods', self.allow_methods)]
        if self.allow_origin != '*':
            self.base_headers.append(
                ('Access-Control-Allow-Origin', self.allow_origin))
        if self.allow_headers:
            self.base_headers.append(
                ('Access-Control-Allow-Headers', self.allow_headers))
        if self.expose_headers:
            # FIXME: first, headers isn't the name
            # Second, like Allow-Origin, maybe this can't be folded?
            self.base_headers.append(
                ('Access-Control-Expose-Header', self.expose_headers))

    def __call__(self, environ, start_response):
        if environ['REQUEST_METHOD'] == 'OPTIONS':
            app = self.options_app
        else:
            app = self.app
        def repl_start_response(status, headers, exc_info=None):
            headers.extend(self.base_headers)
            # Fixes: http://code.google.com/p/chromium/issues/detail?id=67743
            if self.allow_origin == '*':
                origin = environ.get('HTTP_ORIGIN', '*')
                headers.append(
                    ('Access-Control-Allow-Origin', origin))
            if 'Chrome' in environ.get('HTTP_USER_AGENT', ''):
                headers = self.filter_chrome_headers(headers)
            return start_response(status, headers, exc_info)
        return app(environ, repl_start_response)

    def filter_chrome_headers(self, headers):
        new_headers = []
        for name, value in headers:
            if not name.lower().startswith('X-'):
                new_headers.append((name, value))
        return new_headers

    def remove_header(self, headers, remove_name):
        remove_name = remove_name.lower()
        for name, value in headers:
            if name.lower() == remove_name:
                headers.remove((name, value))
                break

    def options_app(self, environ, start_response):
        start_response('200 OK', [])
        return ['']


def includeme(config):
    """Install SyncServer application into the given Pyramid configurator."""
    # Set the umask so that files are created with secure permissions.
    # Necessary for e.g. created-on-demand sqlite database files.
    os.umask(0077)

    # Sanity-check the deployment settings and provide sensible defaults.
    settings = config.registry.settings
    public_url = settings.get("syncserver.public_url")
    if public_url is None:
        raise RuntimeError("you much configure syncserver.public_url")
    public_url = public_url.rstrip("/")
    settings["syncserver.public_url"] = public_url

    secret = settings.get("syncserver.secret")
    if secret is None:
        secret = os.urandom(32).encode("hex")
    sqluri = settings.get("syncserver.sqluri")
    if sqluri is None:
        rootdir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        sqluri = "sqlite:///" + os.path.join(rootdir, "syncserver.db")

    # Configure app-specific defaults based on top-level configuration.
    settings.pop("config", None)
    if "tokenserver.backend" not in settings:
        # Default to our simple static node-assignment backend
        settings["tokenserver.backend"] =\
            "syncserver.staticnode.StaticNodeAssignment"
        settings["tokenserver.sqluri"] = sqluri
        settings["tokenserver.node_url"] = public_url
        settings["endpoints.sync-1.5"] = "{node}/storage/1.5/{uid}"
    if "tokenserver.monkey_patch_gevent" not in settings:
        # Default to no gevent monkey-patching
        settings["tokenserver.monkey_patch_gevent"] = False
    if "tokenserver.applications" not in settings:
        # Default to just the sync-1.5 application
        settings["tokenserver.applications"] = "sync-1.5"
    if "tokenserver.secrets.backend" not in settings:
        # Default to a single fixed signing secret
        settings["tokenserver.secrets.backend"] = "mozsvc.secrets.FixedSecrets"
        settings["tokenserver.secrets.secrets"] = [secret]
    if "tokenserver.allow_new_users" not in settings:
        allow_new_users = settings.get("syncserver.allow_new_users")
        if allow_new_users is not None:
            settings["tokenserver.allow_new_users"] = allow_new_users
    if "hawkauth.secrets.backend" not in settings:
        # Default to the same secrets backend as the tokenserver
        for key in settings.keys():
            if key.startswith("tokenserver.secrets."):
                newkey = "hawkauth" + key[len("tokenserver"):]
                settings[newkey] = settings[key]
    if "storage.backend" not in settings:
        # Default to sql syncstorage backend
        settings["storage.backend"] = "syncstorage.storage.sql.SQLStorage"
        settings["storage.sqluri"] = sqluri
        settings["storage.create_tables"] = True
    if "browserid.backend" not in settings:
        # Default to remote verifier, with base of public_url as only audience
        audience = urlunparse(urlparse(public_url)._replace(path=""))
        settings["browserid.backend"] = "tokenserver.verifiers.RemoteVerifier"
        settings["browserid.audiences"] = audience
    if "loggers" not in settings:
        # Default to basic logging config.
        root_logger = logging.getLogger("")
        if not root_logger.handlers:
            logging.basicConfig(level=logging.INFO)

    # Include the relevant sub-packages.
    config.scan("syncserver")
    config.include("syncstorage", route_prefix="/storage")
    config.include("tokenserver", route_prefix="/token")

    # Add a top-level "it works!" view.
    def itworks(request):
        return Response("it works!")

    config.add_route('itworks', '/')
    config.add_view(itworks, route_name='itworks')


@subscriber(NewRequest)
def reconcile_wsgi_environ_with_public_url(event):
    """Event-listener that checks and tweaks WSGI environ based on public_url.

    This is a simple trick to help ensure that the configured public_url
    matches the actual deployed address.  It fixes fixes parts of the WSGI
    environ where it makes sense (e.g. SCRIPT_NAME) and warns about any parts
    that seem obviously mis-configured (e.g. http:// versus https://).

    It's very important to get public_url and WSGI environ matching exactly,
    since they're used for browserid audience checking and HAWK signature
    validation, so mismatches can easily cause strange and cryptic errors.
    """
    request = event.request
    public_url = request.registry.settings["syncserver.public_url"]
    p_public_url = urlparse(public_url)
    # If we don't have a SCRIPT_NAME, take it from the public_url.
    # This is often the case if we're behind e.g. an nginx proxy that
    # is serving us at some sub-path.
    if not request.script_name:
        request.script_name = p_public_url.path.rstrip("/")
    # If the environ does not match public_url, requests are almost certainly
    # going to fail due to auth errors.  We can either bail out early, or we
    # can forcibly clobber the WSGI environ with the values from public_url.
    # This is a security risk if you've e.g. mis-configured the server, so
    # it's not enabled by default.
    application_url = request.application_url
    if public_url != application_url:
        if not request.registry.settings.get("syncserver.force_wsgi_environ"):
            msg = "\n".join((
                "The public_url setting doesn't match the application url.",
                "This will almost certainly cause authentication failures!",
                "    public_url setting is: %s" % (public_url,),
                "    application url is:    %s" % (application_url,),
                "You can disable this check by setting the force_wsgi_environ",
                "option in your config file, but do so at your own risk.",
            ))
            logger.error(msg)
            raise _JSONError([msg], status_code=500)
        request.scheme = p_public_url.scheme
        request.host = p_public_url.netloc
        request.script_name = p_public_url.path.rstrip("/")


def get_configurator(global_config, **settings):
    """Load a SyncStorge configurator object from deployment settings."""
    config = mozsvc.config.get_configurator(global_config, **settings)
    config.begin()
    try:
        config.include(includeme)
    finally:
        config.end()
    return config


def main(global_config, **settings):
    """Load a SyncStorage WSGI app from deployment settings."""
    config = get_configurator(global_config, **settings)
    application = AccessControlMiddleware(
        config.make_wsgi_app(), allow_origin='*',
        allow_methods=('GET','POST','PUT','DELETE','OPTIONS'),
        allow_headers=('X-Authorization', 'Authorization',
                       'X-If-Modified-Since', 'X-If-Unmodified-Since',
                       'Content-Type', 'X-Requested-With', 'X-Client-State'),
        expose_headers=('X-Weave-Timestamp', 'X-Weave-Backoff',
                        'X-Weave-Alert', 'X-Weave-Records'))
    return application
