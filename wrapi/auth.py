from __future__ import annotations

import typing as t

from httpx import (
    Auth,
    Request,
    Response,
)


WRIKE_AUTH_HEADER_NAME = "Authorization"


class WrikePermanentTokenAuth(Auth):
    def __init__(self, permanent_token: str):
        self.permanent_token = permanent_token

    def auth_flow(self, request: Request) -> t.Generator[Request, Response, None]:
        request.headers[WRIKE_AUTH_HEADER_NAME] = f"bearer {self.permanent_token}"
        yield request


class WrikeRefreshTokenAuth(Auth):
    def __init__(self, access_token: t.Optional[str], refresh_token: str, client_id: str, client_secret: str):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.client_secret = client_secret

    def auth_flow(self, request: Request) -> t.Generator[Request, Response, None]:
        raise NotImplementedError()
        request.headers["X-Authentication"] = self.access_token
        response = yield request
        if response.status_code == 401:
            # If the server issues a 401 response, then issue a request to
            # refresh tokens, and resend the request.
            refresh_response = yield self.build_refresh_request()
            self.update_tokens(refresh_response)

            request.headers["X-Authentication"] = self.access_token
            yield request

    def build_refresh_request(self):
        # Return an `httpx.Request` for refreshing tokens.
        params = {'client_id': self.client_id,'client_secret': self.client_secret, 'grant_type': 'refresh_token', 'scope': 'Default, wsReadWrite', 'refresh_token': self.refresh_token}
        return httpx.post('https://login.wrike.com/oauth2/token', data={ })

    def update_tokens(self, response):
        # Update the `.access_token` and `.refresh_token` tokens
        # based on a refresh response.
        data = response.json()
