import secrets
import time
import requests
from functools import wraps
from flask import Flask, redirect, session, url_for
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc6749 import OAuth2Token

KEYCLOAK_SERVER_URL = "your-server-url"
KEYCLOAK_REALM = "your-realm"
KEYCLOAK_CLIENT_ID = "your-client-id"
KEYCLOAK_CLIENT_SECRET = "your-client-secret"

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)

# For manually refreshing tokens
# def updateToken(name, token, refresh_token=None, access_token=None):
#     if refresh_token:
#         item = OAuth2Token.find(name=name, refresh_token=refresh_token)
#     elif access_token:
#         item = OAuth2Token.find(name=name, access_token=access_token)
#     else:
#         return

#     # Updating old token
#     item.access_token = token["access_token"]
#     item.refresh_token = token.get("refresh_token")
#     item.expires_at = token["expires_at"]
#     item.save()


oauth = OAuth(app)  # , update_token=updateToken) - Manual refreshing of tokens

SERVER_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
API_BASE_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect"
AUTHORIZATION_URL = f"{API_BASE_URL}/auth"
REGISTRATION_URL = f"{API_BASE_URL}/registrations"
TOKEN_URL = f"{API_BASE_URL}/token"
REVOCATION_URL = f"{API_BASE_URL}/logout"

oauth.register(
    name="keycloak",
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret=KEYCLOAK_CLIENT_SECRET,
    server_metadata_url=SERVER_URL,
    token_endpoint=TOKEN_URL,  # Automatic refreshing of tokens
    client_kwargs={
        "scope": "openid email profile",
        "code_challenge_method": "S256"
    },
)


def loginRequired(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token")
        expires_at = session.get("expires_at")
        if not token or expires_at is None or expires_at < time.time():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def home():
    return "Home page (public content)"


# @app.route("/signup")
# def signup():
#     data = {
#         "client_id": KEYCLOAK_CLIENT_ID,
#         "client_secret": KEYCLOAK_CLIENT_SECRET,
#         "Content-Type": "application/x-www-form-urlencoded",
#         "grant_type": "client_credentials",
#         "nonce": secrets.token_urlsafe(16)
#     }

#     response = requests.post(AUTHORIZATION_URL, data=data)
#     response.raise_for_status()
#     access_token = response.json()["access_token"]

#     headers = {
#         "Authorization": f"Bearer {access_token}",
#         "Content-Type": "application/x-www-form-urlencoded"
#     }
#     response = requests.get(REGISTRATION_URL, headers=headers)
#     response.raise_for_status()
#     return response.text


@app.route("/login")
def login():
    session["nonce"] = secrets.token_urlsafe(16)
    redirect_uri = url_for("authorize", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri, nonce=session["nonce"])


@app.route("/authorize")
def authorize():
    token = oauth.keycloak.authorize_access_token()
    session["token"] = token["access_token"]
    session["refresh_token"] = token["refresh_token"]
    session["expires_at"] = token["expires_at"]
    userinfo = oauth.keycloak.parse_id_token(token, nonce=session.get("nonce"))
    # Save user info or perform any necessary actions

    return redirect(url_for("index"))


@app.route("/index")
@loginRequired
def index():
    token = session.get("token")
    expires_at = session.get("expires_at")
    if not token or expires_at is None or expires_at < time.time():
        return redirect(url_for("login"))

    token_obj = OAuth2Token({
        "token_type": "Bearer",
        "access_token": token,
        "refresh_token": session.get("refresh_token"),
        "expires_at": session.get("expires_at"),
    })

    userinfo = oauth.keycloak.userinfo(token=token_obj)
    # Access token is valid and user is logged in, perform necessary actions
    return f"Protected content<br><br>{userinfo}"


@app.route("/logout")
def logout():
    access_token = session.get("token")

    if access_token:
        refresh_token = session.get("refresh_token")
        data = {
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "refresh_token": refresh_token
        }
        response = requests.post(REVOCATION_URL, data=data)
        if not response.ok:
            return "Failed to revoke access token"

    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
