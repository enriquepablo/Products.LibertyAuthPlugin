import os

# Zope
from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from zLOG import LOG, INFO, ERROR, WARNING

import lasso

# Local
from FederationBase import FederationBase
import Saml
import Liberty

class LibAuth(FederationBase):
    security = ClassSecurityInfo()

    # Allow access to the following instance attributes
    security.declarePublic('liberty')
    security.declarePublic('saml')

    def __init__(self, controller):
        self.config = controller.config
        self.federations = controller.federations
        self.userTokens = controller.userTokens

        if self.config['generateMetadataAndKeys']:
            self.set_provider_keys()

        self.liberty = Liberty.Liberty(controller)
        self.saml = Saml.Saml(controller)

    def set_provider_keys(self):
        # FIXME: use a proper way to generate private and public key files :
        os.system('openssl genrsa -out %s 2048' % (self.config['privatekey_path']))
        os.system('openssl rsa -in %s -pubout -out %s' % (self.config['privatekey_path'],
                                                          self.config['publickey_path']))

    def get_current_protocol(self, context):
        providers = self.get_identity_providers()
        if not providers:
            LOG('', ERROR, 'No identity provider configured')
            # FIXME: Return to error page
            return self.config['root_url']

        provider_config = providers[0]
        provider = lasso.Provider(lasso.PROVIDER_ROLE_IDP,
                                  provider_config['metadata_path'],
                                  provider_config['publickey_path'],
                                  None)
        return provider.getProtocolConformance()

    security.declarePublic('signOn')
    def signOn(self, context):
        if self.get_current_protocol(context) == lasso.PROTOCOL_SAML_2_0:
            return self.saml.sso(context)
        else:
            return self.liberty.sso(context)

    security.declarePublic('signOut')
    def signOut(self, context):
        if self.get_current_protocol(context) == lasso.PROTOCOL_SAML_2_0:
            return self.saml.singleLogoutSP(context)
        else:
            return self.liberty.singleLogout(context)

    security.declarePublic('completeUserRegisteredFederation')
    def completeUserRegisteredFederation(self, context):
        request = context.REQUEST
        session = request.SESSION
        acl_users = context.acl_users

        userId = request.form['userId']
        # FIXME: Not sure it is the right method to use (a method like addUser() must exist ... ).
        acl_users._doAddUser(userId, userId, [], [])

        return self.completeAssertionConsumerService(context, userId)

    security.declarePublic('completeUserTokenRegistration')
    def completeUserTokenRegistration(self, context):
        request = context.REQUEST
        session = request.SESSION

        userToken = request.form.get('userToken')
        if userToken is None:
            query_string = request.QUERY_STRING
            splitted = query_string.strip('/').split('&')
            tuples = {}
            for c in splitted:
                key, value = c.split('=')
                tuples[key] = value
            userToken = tuples['userToken']

        userId = self.userTokens.getUserId(userToken)
        self.userTokens.removeToken(userToken)

        return self.completeAssertionConsumerService(context, userId)

    def completeAssertionConsumerService(self, context, userId):
        request = context.REQUEST
        session = request.SESSION

        nameIdentifier = session['nameIdentifier']
        identityDump = session['identityDump']
        if identityDump:
            del session['identityDump']

        LOG('LibAuth completeAssertionConsumerService :', INFO, 'name identifier : %s, user id : %s' % (nameIdentifier, userId))

        self.federations.setFederation(nameIdentifier, userId, identityDump)

        # FIXME: If a relay state, returns to it instead.
        return self.config['root_url']

InitializeClass(LibAuth)
