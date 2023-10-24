import json
import base64
import hashlib
import secrets
from requests_oauthlib import OAuth2Session
import urllib.parse
import os

#Necessary to avoid SSL check
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

"""
--------------- UTIL -------------------
"""
def make_code_challenge(code_verifier):
    code_challenge_sha256 = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_sha256).decode().rstrip("=")
    return code_challenge
def json_dumps_beauty(data):
	return json.dumps(data, ensure_ascii = False, indent = 4)

def make_basic_auth_headers(username, password):
	credential = "{}:{}".format(username, password)
	authorization = base64.b64encode(credential.encode("utf-8")).decode("utf-8")

	return {
		"Content-Type": "application/x-www-form-urlencoded",
		"Authorization": "Basic {}".format(authorization)
	}
pass  # def

"""
--------------- FUNCTIONAL METHODS ------------------- 
"""
def make_authorize_request(t): #client_id, redirect_uri, scopes,
    state = secrets.token_urlsafe(64)
    code_verifier = secrets.token_urlsafe(128)
    code_challenge = make_code_challenge(code_verifier)

    #t = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)
    authorization_url, state = t.authorization_url(
        "https://twitter.com/i/oauth2/authorize",
        code_challenge=code_challenge,
        code_challenge_method="S256",
        state=state
    )

    # Imprime o almacena la URL de autorización para que el usuario la utilice
    print("[Authorize Request URL]")
    print("=" * 70)
    print(authorization_url)
    print("=" * 70)

    return state, code_verifier

def get_access_token(t, client_secret, code_verifier, auth_code): #client_id, client_secret, redirect_uri, code_verifier, auth_code
    token_url = "https://api.twitter.com/2/oauth2/token"

    token = t.fetch_token(
        token_url,
        code=auth_code,
        code_verifier=code_verifier,
        client_secret=client_secret,
    )

    return token

"""
--------------- MAIN -------------------
"""
def main():
    #Set const Auth 2.0 w/
    client_id = "bzVNelA1S2FZVnQzUXN1cWdMSlQ6MTpjaQ"
    client_secret = "shNQHuB5UJKldXpyGTuFbmozcX9UU_TP6d0mNaFj6SMiYu231M"
    redirect_uri = "https://localhost" #"http://localhost:3000/twitter/redirect"
    scopes = ["tweet.write", "tweet.read", "users.read", "offline.access"]

    #Make an auth session
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)

    #Make url
    state, code_verifier = make_authorize_request(oauth)

    #Request redirect url to user
    url = input("Paste redirect URL here:\n=> ")
    url = url.strip()

    #Get state and auth code
    parsed = urllib.parse.urlparse(url)
    query_d = urllib.parse.parse_qs(parsed.query)
    auth_code = query_d.get("code")[0]
    state_received = query_d.get("state")[0]
    #print("Code url", auth_code)

    #Check previous request status
    if state_received == state:
        #Get access token
        get_access_token(
            oauth,
            client_secret,
            code_verifier,
            auth_code
        )

    #-------- TEST 1 (GET /2/users/me) ----------------
    fields = "created_at,description"
    params = {"user.fields": fields}

    response = oauth.get(
        "https://api.twitter.com/2/users/me", params=params
    )

    json_response = response.json()
    print("--- OUTPUT TEST 1")
    print(json_dumps_beauty(json_response))

    # -------- TEST 2 (GET /2/users/by) ----------------
    params = {"usernames": "Spaces,X", "user.fields": fields}

    response = oauth.get(
        "https://api.twitter.com/2/users/by", params=params
    )

    json_response = response.json()

    print("--- OUTPUT TEST 2")
    print(json.dumps(json_response, indent=4, sort_keys=True))

    # -------- TEST 3 (GET /2/tweets) ----------------
    id_account = "1445068515229192199"
    params = {"usernames": id_account, "tweet.fields": "created_at,context_annotations,entities,conversation_id,author_id", "user.fields": fields}

    response = oauth.get(
        "https://api.twitter.com/2/tweets", params=params
    )

    json_response = response.json()

    print("--- OUTPUT TEST 3")
    print(json.dumps(json_response, indent=4, sort_keys=True))

    # -------- TEST 4 (GET /2/tweets/search/recent) ----------------
    query = """has:geo (from:NWSNHC OR from:NHC_Atlantic OR from:NWSHouston OR from:NWSSanAntonio 
    OR from:USGS_TexasRain OR from:USGS_TexasFlood OR from:JeffLindner1) -is:retweet"""
    params = {"query": query,
              "tweet.fields": "created_at,context_annotations,entities,conversation_id,author_id",
              "media.fields": "duration_ms,height,media_key,preview_image_url,type,url,width,public_metrics",
              "user.fields": fields}

    response = oauth.get(
        "https://api.twitter.com/2/tweets/search/recent", params=params
    )

    json_response = response.json()

    print("--- OUTPUT TEST 4")
    print(json.dumps(json_response, indent=4, sort_keys=True))


pass  # def

if __name__ == "__main__":
    main()
