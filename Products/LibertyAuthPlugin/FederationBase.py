import os
import urllib
import httplib
import base64

# Zope
from AccessControl import ClassSecurityInfo
from Globals import Persistent
from zLOG import LOG, INFO, ERROR, WARNING

import lasso

class FederationBase(Persistent):
    security = ClassSecurityInfo()

    def get_key_descriptor(self):
        publickey_path = self.config['publickey_path']
        if not os.path.exists(publickey_path):
            LOG('', WARNING, 'get_key_descriptor(): no public key file (%s)' % publickey_path)
            return ''
        pem_key = open(publickey_path).read()

        key_type = 'signing'

        if 'CERTIF' in pem_key:
            pem_key = pem_key.strip()
            pem_key = pem_key.strip('-----BEGIN CERTIFICATE-----')
            pem_key = pem_key.strip('-----END CERTIFICATE-----')
            pem_key = pem_key.strip()
            key_descriptor = """
    <KeyDescriptor use="%s">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>""" % (key_type, pem_key)
        elif 'KEY' in pem_key:
            pem_key = pem_key.strip()
            pem_key = pem_key.strip('-----BEGIN PUBLIC KEY-----')
            pem_key = pem_key.strip('-----END PUBLIC KEY-----')
            pem_key = pem_key.strip()
            key_descriptor = """
    <KeyDescriptor use="%s">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:KeyValue>%s</ds:KeyValue>
      </ds:KeyInfo>
    </KeyDescriptor>""" % (key_type, pem_key)
        else:
            key_descriptor = ''

        return key_descriptor

    security.declarePublic('get_identity_providers')
    def get_identity_providers(self):
        providers_home = self.config['providers_home']
        try:
            providers_path_list = os.listdir(providers_home)
        except:
            LOG('', WARNING, 'No identity provider configured')
            return []

        providers = []
        for p in providers_path_list:
            metadata_path = '%s/%s/metadata.xml' % (providers_home, p)
            publickey_path = '%s/%s/publickey.pem' % (providers_home, p)
            if not os.path.exists(publickey_path):
                publickey_path = None
            providers.append({'name' : p, 'metadata_path' : metadata_path, 'publickey_path' : publickey_path})
        return providers

    def get_lasso_server(self, protocol):
        server = lasso.Server(self.config[protocol]['metadata_path'],
                                   self.config['privatekey_path'],
                                   None, None)
        providers_filenames = []
        try:
            providers_filenames = os.listdir(self.config['providers_home'])
        except OSError:
            LOG('', ERROR, 'No identity provider configured')

        for provider in self.get_identity_providers():
            server.addProvider(lasso.PROVIDER_ROLE_IDP, provider['metadata_path'],
                               provider['publickey_path'], None)
        return server

    def get_relay_state(self, context):
        """If there is a RelayState in the URL, give it to Lasso Login"""
        query_string = context.REQUEST.QUERY_STRING
        if query_string:
            splitted = query_string.strip('/').split('&')
            tuples = {}
            for c in splitted:
                key, value = c.split('=', 1)
                tuples[key] = value
            return tuples.get('RelayState')
        return None

    def set_sso_relay_state(self, login, context):
        relay_state = self.get_relay_state(context)
        if relay_state:
            login.request.relayState = relay_state

    def error_page(self, msg):
        LOG('', ERROR, msg)
        # FIXME: Return to an error page
        return self.config['root_url']

    def soap_call(self, url, msg, client_cert = None):
        if url.startswith('http://'):
            host, query = urllib.splithost(url[5:])
            conn = httplib.HTTPConnection(host)
        else:
            host, query = urllib.splithost(url[6:])
            conn = httplib.HTTPSConnection(host,
                    key_file = client_cert, cert_file = client_cert)
        conn.request('POST', query, msg, {'Content-Type': 'text/xml'})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        if response.status not in (200, 204): # 204 ok for federation termination
            LOG('', ERROR, 'SOAP error (%s) (on %s)' % (response.status, url))
            return None
        return data

    def sso_finish_processing(self, context, login):
        request = context.REQUEST
        session = request.SESSION

        if login.nameIdentifier:
            nameIdentifier = login.nameIdentifier.content
        else:
            nameIdentifier = None
        session['nameIdentifier'] = nameIdentifier

        if login.identity:
            identityDump = login.identity.dump()
        else:
            identityDump = None

        if login.session:
            session['sessionDump'] = login.session.dump()
        else:
            session['sessionDump'] = None

        user_id = self.federations.getUserId(nameIdentifier)
        if user_id:
            LOG('', INFO, 'User already federated :' + user_id)
            next_url = self.config['root_url']
        else:
            LOG('', INFO, 'User not federated yet')
            session['identityDump'] = identityDump
            relay_state = self.get_relay_state(context)
            if relay_state:
                next_url = base64.decodestring(relay_state)
            else:
                next_url = '%s/chooseFederationMethod' % self.config['libauth']['libauth_url']

        return next_url

    def getSessionFromNameIdentifier(self, session_data, nameIdentifier):
        for session in session_data.items():
            contents = session[1]
            ni = contents.get('nameIdentifier')
            if ni and ni == nameIdentifier:
                return session
        return None
