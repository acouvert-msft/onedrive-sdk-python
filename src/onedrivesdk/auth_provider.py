'''
------------------------------------------------------------------------------
 Copyright (c) 2015 Microsoft Corporation

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
------------------------------------------------------------------------------
'''
from __future__ import unicode_literals
import json
from .auth_provider_base import AuthProviderBase
from .options import *
from .session import Session
import time
import sys

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


class AuthProvider(AuthProviderBase):

    AUTH_DEVICECODE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
    AUTH_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"

    def __init__(self, http_provider, client_id=None, scopes=None, loop=None):
        """Initialize the authentication provider for authenticating
        requests sent to OneDrive

        Args:
            http_provider (:class:`HttpProviderBase<onedrivesdk.http_provider_base>`):
                The HTTP provider to use for all auth requests
            client_id (str): Defaults to None, the client id for your
                application
            scopes (list of str): Defaults to None, the scopes
                that are required for your application
            loop (BaseEventLoop): Defaults to None, the asyncio
                loop to use for all async requests. If none is provided,
                asyncio.get_event_loop() will be called. If using Python
                3.3 or below this does not need to be specified
        """
        self._http_provider = http_provider
        self._client_id = client_id
        self._scopes = scopes

        self._auth_devicecode_url = self.AUTH_DEVICECODE_URL
        self._auth_token_url = self.AUTH_TOKEN_URL
        self._access_token = None
        self._refresh_token = None

        if sys.version_info >= (3, 4, 0):
            import asyncio
            self._loop = loop if loop else asyncio.get_event_loop()

    def authenticate_request(self, request):
        """Append the required authentication headers
        to the specified request. This will only function
        if a session has been successfully created using
        :func:`authenticate`. This will also refresh the
        authentication token if necessary.

        Args:
            request (:class:`RequestBase<onedrivesdk.request_base.RequestBase>`):
                The request to authenticate
        """
        if self._access_token is None and 'wl.offline_access' in self._scopes:
            self.refresh_token()

        request.append_option(
            HeaderOption("Authorization",
                         "bearer {}".format(self._access_token)))

        self._access_token = None

    def device_code(self, on_new_user_code):
        params = {
            "client_id": self._client_id
        }
        if self._scopes is not None:
            params["scope"] = " ".join(self._scopes)

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self._http_provider.send(method="POST",
                                            headers=headers,
                                            url=self._auth_devicecode_url,
                                            data=params)
        if response.status != 200:
            return

        rcont = json.loads(response.content)

        on_new_user_code(rcont["verification_uri"], rcont["user_code"])

        expires_in = rcont["expires_in"]
        interval = rcont["interval"]

        while expires_in > 0:
            try:
                params = {
                    "client_id": self._client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": rcont["device_code"]
                }

                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                response = self._http_provider.send(method="POST",
                                                    headers=headers,
                                                    url=self._auth_token_url,
                                                    data=params)
                rcont = json.loads(response.content)
                print(rcont)
            except Exception as exception:
                print(exception)
                time.sleep(interval)
                expires_in -= interval
                continue

            if response.status == 200:
                break

        self._access_token = rcont["access_token"]
        self._refresh_token = rcont["refresh_token"]

    def refresh_token(self):
        """Refresh the token currently used by the session"""
        if self._refresh_token is None:
            raise RuntimeError("""Refresh token not present.""")

        params = {
            "refresh_token": self._refresh_token,
            "client_id": self._client_id,
            "grant_type": "refresh_token"
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self._http_provider.send(method="POST",
                                            headers=headers,
                                            url=self._auth_token_url,
                                            data=params)
        rcont = json.loads(response.content)

        if response.status != 200:
            return

        self._access_token = rcont["access_token"]
        self._refresh_token = rcont["refresh_token"]

    def save_session(self, **save_session_kwargs):
        """Save the current session. Must have already
        obtained an access_token.

        Args:
            save_session_kwargs (dict): Arguments to
                be passed to save_session.
        """
        if self._session is None:
            raise RuntimeError("""Session must be authenticated before
            it can be saved. """)
        self._session.save_session(**save_session_kwargs)

    def load_session(self, **load_session_kwargs):
        """Load session. This will overwrite the current session.

        Args:
            load_session_kwargs (dict): Arguments to
                be passed to load_session.
        """
        self._session = self._session_type.load_session(**load_session_kwargs)
