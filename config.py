import os

tenant_id = os.environ['tenant_id']
client_id = os.environ['client_id']
client_secret = os.environ['client_secret']
policy_name = 'B2C_1_b2c_signin_signup'

scopes = ['openid','offline_access',client_id]

core_url = 'https://login.microsoftonline.com/tfp/' + tenant_id + '/' + policy_name
refresh_url = 'https://krassyb2cc.b2clogin.com/krassyb2cc.onmicrosoft.com/oauth2/v2.0/token?p=B2C_1_b2c_signin_signup'
token_url = core_url + '/oauth2/v2.0/token'
authorize_url = core_url + '/oauth2/v2.0/authorize'
keys_url = core_url + '/discovery/keys'

