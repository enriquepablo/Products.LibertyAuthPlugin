import os
import urllib

# Zope
from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from zLOG import LOG, INFO, ERROR, WARNING

import lasso

# Local
from FederationBase import FederationBase

class Saml(FederationBase):
    security = ClassSecurityInfo()

    def __init__(self, controller):
        self.config = controller.config
        self.federations = controller.federations

        if self.config['generateMetadataAndKeys']:
            self.set_provider_metadata()

    def set_provider_metadata(self):
        saml_url = self.config['saml']['saml_url']
        metadata_config = {
            'entity_id': self.config['saml']['metadata_url'],
            'key_descriptor': self.get_key_descriptor(),
            'assertion_consumer_service_artifact_url': saml_url + '/singleSignOnArtifact',
            'single_logout_service_redirect': saml_url + '/singleLogout',
            'single_logout_service_redirect_return': saml_url + '/singleLogoutReturn',
            'single_logout_service_soap': saml_url + '/singleLogoutSOAP',
            'manage_name_id_service_redirect': saml_url + '/manageNameId',
            'organisation_name': self.config['organisation_name'],
        }

        metadata_content = '''<?xml version="1.0"?>
<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="%(entity_id)s">

  <SPSSODescriptor
    AuthnRequestsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%(key_descriptor)s

    <AssertionConsumerService isDefault="true" index="0"
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
      Location="%(assertion_consumer_service_artifact_url)s" />

    <SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="%(single_logout_service_redirect)s"
      ResponseLocation="%(single_logout_service_redirect_return)s" />

    <ManageNameIDService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="%(manage_name_id_service_redirect)s" />

  </SPSSODescriptor>

  <Organization>
    <OrganizationName xml:lang="en">%(organisation_name)s</OrganizationName>
  </Organization>

</EntityDescriptor>''' % metadata_config

        try:
            open(self.config['saml']['metadata_path'], 'w').write(metadata_content)
        except IOError, err:
            LOG('', ERROR, err)

    def getLassoServer(self):
        return self.get_lasso_server('saml')

    def sso(self, context):
        server = self.getLassoServer()
        if not server:
            return self.error_page('Failed building lasso server')
        login = lasso.Login(server)
        login.initAuthnRequest(server.providerIds[0], lasso.HTTP_METHOD_REDIRECT)
        login.request.nameIDPolicy.format = lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT
        login.request.nameIDPolicy.allowCreate = True
        login.request.forceAuthn = False
        login.request.isPassive = False
        login.request.consent = 'urn:oasis:names:tc:SAML:2.0:consent:current-implicit'
        login.buildAuthnRequestMsg()

        self.set_sso_relay_state(login, context)

        return login.msgUrl

    security.declarePublic('singleSignOnArtifact')
    def singleSignOnArtifact(self, context):
        request = context.REQUEST
        session = request.SESSION
        query_string = urllib.unquote(request.get('QUERY_STRING'))

        server = self.getLassoServer()
        if not server:
            return self.error_page('Failed building lasso server')
        login = lasso.Login(server)

        try:
            login.initRequest(query_string, lasso.HTTP_METHOD_ARTIFACT_GET)
        except lasso.Error, error:
            if error[0] == lasso.PROFILE_ERROR_MISSING_ARTIFACT:
                return self.error_page('Missing SAML Artifact')
            elif error[0] == lasso.PROFILE_ERROR_MISSING_REMOTE_PROVIDERID:
                return self.error_page('Authentication request initiated by an unaffiliated provider')
            else:
                raise

        login.buildRequestMsg()

        soap_response = self.soap_call(login.msgUrl, login.msgBody)
        if not soap_response:
            return self.error_page('No SOAP response from identity provider')

        try:
            login.processResponseMsg(soap_response)
        except lasso.Error, error:
            if error[0] == lasso.LOGIN_ERROR_STATUS_NOT_SUCCESS:
                return self.error_page('Unknown authentication failure')
            if error[0] == lasso.LOGIN_ERROR_UNKNOWN_PRINCIPAL:
                return self.error_page('Authentication failure; unknown principal')
            if error[0] == lasso.LOGIN_ERROR_FEDERATION_NOT_FOUND:
                return self.error_page('Authentication failure; federation not found')
            raise

        return self.sso_after_response(context, login)

    def sso_after_response(self, context, login):
        assertion = login.response.assertion[0]

        # TODO: Check assertion validity

        login.acceptSso()

        return self.sso_finish_processing(context, login)

    security.declarePublic('singleLogoutSP')
    def singleLogoutSP(self, context):
        request = context.REQUEST
        session = request.SESSION

        logout = lasso.Logout(self.getLassoServer())

        sessionDump = session.get('sessionDump')
        nameIdentifier = session.get('nameIdentifier')
        identityDump = self.federations.getIdentityDump(nameIdentifier)

        if sessionDump:
            logout.setSessionFromDump(sessionDump)
        if identityDump:
            logout.setIdentityFromDump(identityDump)

        return self.slo_sp_redirect(context, logout)

    def slo_sp_redirect(self, context, logout):
        request = context.REQUEST
        try:
            logout.initRequest(None, lasso.HTTP_METHOD_REDIRECT)
        except lasso.Error, error:
            if error[0] == lasso.PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND:
                context.acl_users.logout(request)
                return self.config['root_url']
            if error[0] == lasso.PROFILE_ERROR_SESSION_NOT_FOUND:
                context.acl_users.logout(request) 
                return self.config['root_url']
            raise

        logout.buildRequestMsg()
        return logout.msgUrl

    security.declarePublic('singleLogoutReturn')
    def singleLogoutReturn(self, context):
        request = context.REQUEST
        session = request.SESSION
        query_string = request.get('QUERY_STRING')

        logout = lasso.Logout(self.getLassoServer())

        sessionDump = session.get('sessionDump')
        nameIdentifier = session.get('nameIdentifier')

        if sessionDump:
            logout.setSessionFromDump(sessionDump)

        try:
            logout.processResponseMsg(query_string)
        except lasso.Error, error:
            if error[0] == lasso.PROFILE_ERROR_INVALID_QUERY:
                LOG('Saml singleLogoutReturn :', WARNING, 'Invalid response')
            elif error[0] == lasso.DS_ERROR_INVALID_SIGNATURE:
                LOG('Saml singleLogoutReturn :', WARNING, 'Failed to check single logout response signature')
            elif error[0] == lasso.LOGOUT_ERROR_REQUEST_DENIED:
                LOG('Saml singleLogoutReturn :', WARNING, 'Request Denied')
            elif error[0] == lasso.LOGOUT_ERROR_UNKNOWN_PRINCIPAL:
                LOG('Saml singleLogoutReturn :', WARNING, 'Unknown principal on logout, probably session stopped already on IdP')
            else:
                raise

        if sessionDump:
            del session['sessionDump']
        if nameIdentifier:
            del session['nameIdentifier']

        context.acl_users.logout(request) 

        return self.config['root_url']

    def slo_idp(self, logout, session):
        name_identifier = logout.nameIdentifier.content

        session_dump = session.get('sessionDump')
        if session_dump:
            logout.setSessionFromDump(session_dump)

        identity_dump = self.federations.getIdentityDump(name_identifier)
        if identity_dump:
            logout.setIdentityFromDump(identity_dump)

        try:
            assertion = logout.session.getAssertions(logout.remoteProviderId)[0]
            if logout.request.sessionIndex and (
                    assertion.authnStatement[0].sessionIndex != logout.request.sessionIndex):
                logout.setSessionFromDump('<Session />')
        except:
            pass
        
        try:
            logout.validateRequest()
        except lasso.Error, error:
            if error[0] == lasso.DS_ERROR_INVALID_SIGNATURE:
                # FIXME in Lasso : make signature and signature validation work
                LOG('Saml slo_idp :', WARNING, 'Failed to check single logout request signature')
            elif error[0] == lasso.PROFILE_ERROR_SESSION_NOT_FOUND:
                pass
            elif error[0] == lasso.PROFILE_ERROR_IDENTITY_NOT_FOUND:
                pass
            elif error[0] == lasso.PROFILE_ERROR_MISSING_ASSERTION:
                pass
            else:
                raise

        session.invalidate()

        logout.buildResponseMsg()
        if logout.msgBody:
            return '200', logout.msgBody
        else:
            return logout.msgUrl

    security.declarePublic('singleLogout')
    def singleLogout(self, context):
        request = context.REQUEST
        session = request.SESSION
        query_string = urllib.unquote(request.get('QUERY_STRING'))

        logout = lasso.Logout(self.getLassoServer())
        try:
            logout.processRequestMsg(query_string)
        except lasso.Error, error:
            if error[0] == lasso.DS_ERROR_INVALID_SIGNATURE:
                # FIXME in Lasso : make signature and signature validation work
                #return self.error_page('Failed to check single logout request signature.')
                pass
            else:
                raise

        return self.slo_idp(logout, session)

    security.declarePublic('singleLogoutSOAP')
    def singleLogoutSOAP(self, session_data, soap_request_msg):
        # FIXME: this binding doesn't work yet and thus is not included in generated metadata
        request_type = lasso.getRequestTypeFromSoapMsg(soap_request_msg) 

        if request_type != lasso.REQUEST_TYPE_LOGOUT:
            LOG('Saml singleLogoutSOAP :', WARNING, 'SOAP message on single logout url not a slo message')
            return 500, None

        logout = lasso.Logout(self.getLassoServer())
        logout.processRequestMsg(soap_request_msg)
        name_identifier = logout.nameIdentifier.content

        session = self.getSessionFromNameIdentifier(session_data, name_identifier)
        if not session:
            # No session, build straight failure answer
            logout.buildResponseMsg()
            return '200', logout.msgBody

        return self.slo_idp(logout, session[1])

    def manage_name_id(self, manage):
        name_identifier = manage.nameIdentifier.content

        identity_dump = self.federations.getIdentityDump(name_identifier)
        if identity_dump:
            manage.setIdentityFromDump(identity_dump)

        try:
            manage.validateRequest()
        except lasso.Error, error:
            raise

        self.federations.removeFederation(name_identifier)

        manage.buildResponseMsg()

    security.declarePublic('manageNameId')
    def manageNameId(self, context):
        request = context.REQUEST
        session = request.SESSION
        query_string = urllib.unquote(request.get('QUERY_STRING'))

        manage = lasso.NameIdManagement(self.getLassoServer())
        manage.processRequestMsg(query_string)

        if session.get('nameIdentifier'):
            del session['nameIdentifier']
        if session.get('sessionDump'):
            del session['sessionDump']

        self.manage_name_id(manage)

        return manage.msgUrl

InitializeClass(Saml)
