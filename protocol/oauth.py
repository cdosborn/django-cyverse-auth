import requests
from authentication import jwt

from atmosphere import settings

# Requests auth class for access tokens
class BearerTokenAuth(requests.auth.AuthBase):
    """
    Authentication using the protocol:
    Bearer <access_token>
    """
    def __init__(self, access_token):
        self.access_token = access_token

    def __call__(self, r):
        r.headers['Authorization'] = "Bearer %s" % self.access_token
        return r


def is_atmo_user(username):
    access_token = generate_access_token(
                    open(settings.OAUTH_PRIVATE_KEY).read(),
                    iss=settings.OAUTH_ISSUE_USER,
                    scope=settings.OAUTH_SCOPE)
    response = requests.get('%s/api/groups/atmo-user/members' % settings.GROUPY_SERVER)
    atmo_users = [user['name'] for user in response.json()['data']]
    return username in atmo_users


def generate_access_token(pem_id_key, iss='atmosphere', scope='groups', sub=None):
    if not pem_id_key:
        raise Exception("Private key missing. Key is required for JWT signature")
    #1. Create and encode JWT (using our pem key)
    kwargs = {'iss':iss,
              'scope': scope}
    if sub:
        kwargs['sub'] = sub
    jwt_object = jwt.create(**kwargs)
    encoded_sig = jwt.encode(jwt_object, pem_id_key)
    
    #2. Pass JWT to gables and return access_token
    #If theres a 'redirect_uri' then redirect the user
    response = requests\
        .post("%s/o/oauth2/token" % settings.GROUPY_SERVER,
              data={
                  'assertion':encoded_sig,
                  'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer'})
    if response.status_code != 200:
        raise Exception("Failed to generate auth token. Response:%s" % response)
    json_obj = response.json()
    access_token = json_obj['access_token']
    return access_token


def read_access_token(access_token):
    payload = {'access_token': access_token}
    response = requests.get("%s/o/oauth2/tokeninfo" % settings.GROUPY_SERVER, params=payload)
    if response.status_code != 200:
        raise Exception("Failed to read auth token. Response:%s" % response)
    return response.text


def generate_keys():
    """
    Note: This doesnt work.
    """
    response = requests.post("%s/apps/groupy/keys" % settings.GROUPY_SERVER)
    if response.status_code != 200:
        raise Exception("Failed to generate auth token. Response:%s" % response)
    json_obj = response.json()
    pem_id_key = json_obj['private']
    return pem_id_key

