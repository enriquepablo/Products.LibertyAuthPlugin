import os
import urllib
import urlparse

# Zope
from AccessControl import ClassSecurityInfo, getSecurityManager
from Globals import InitializeClass
from zLOG import LOG, INFO, ERROR, WARNING

import lasso

# Local
from FederationBase import FederationBase

class Liberty(FederationBase):
    security = ClassSecurityInfo()

    def __init__(self, controller):
        self.config = controller.config
        self.federations = controller.federations

        if self.config['generateMetadataAndKeys']:
            self.set_provider_metadata()

    def set_provider_metadata(self):
        liberty_url = self.config['liberty']['liberty_url']
        metadata_config = {
            'provider_id': self.config['liberty']['metadata_url'],
            'key_descriptor': self.get_key_descriptor(),
            'soap_endpoint': liberty_url + '/soapEndpoint',
            'assertion_consumer_service_url': liberty_url + '/assertionConsumerService',
            'single_logout_service_url': liberty_url + '/singleLogout',
            'single_logout_service_return_url': liberty_url + '/singleLogoutReturn',
            'federation_termination_service_url': liberty_url + '/federationTermination',
            'organisation_name': self.config['organisation_name'],
        }

        metadata_content = '''<?xml version="1.0"?>
<EntityDescriptor
    providerID="%(provider_id)s"
    xmlns="urn:liberty:metadata:2003-08">

  <SPDescriptor protocolSupportEnumeration="urn:liberty:iff:2003-08">
%(key_descriptor)s

    <SoapEndpoint>%(soap_endpoint)s</SoapEndpoint>

    <AuthnRequestsSigned>true</AuthnRequestsSigned>
    <AssertionConsumerServiceURL id="AssertionConsumerService1" isDefault="true">%(assertion_consumer_service_url)s</AssertionConsumerServiceURL>

    <SingleLogoutServiceURL>%(single_logout_service_url)s</SingleLogoutServiceURL>
    <SingleLogoutServiceReturnURL>%(single_logout_service_return_url)s</SingleLogoutServiceReturnURL>
    <SingleLogoutProtocolProfile>http://projectliberty.org/profiles/slo-idp-soap</SingleLogoutProtocolProfile>
    <SingleLogoutProtocolProfile>http://projectliberty.org/profiles/slo-idp-http</SingleLogoutProtocolProfile>
    <SingleLogoutProtocolProfile>http://projectliberty.org/profiles/slo-sp-http</SingleLogoutProtocolProfile>

    <FederationTerminationServiceURL>%(federation_termination_service_url)s</FederationTerminationServiceURL>
    <FederationTerminationNotificationProtocolProfile>http://projectliberty.org/profiles/fedterm-idp-soap</FederationTerminationNotificationProtocolProfile>
    <FederationTerminationNotificationProtocolProfile>http://projectliberty.org/profiles/fedterm-idp-http</FederationTerminationNotificationProtocolProfile>
    <FederationTerminationNotificationProtocolProfile>http://projectliberty.org/profiles/fedterm-sp-soap</FederationTerminationNotificationProtocolProfile>

  </SPDescriptor>

  <Organization>
    <OrganizationName>%(organisation_name)s</OrganizationName>
  </Organization>

</EntityDescriptor>
    ''' % metadata_config

        try:
            open(self.config['liberty']['metadata_path'], 'w').write(metadata_content)
        except IOError, err:
            LOG('', ERROR, err)

    def getLassoServer(self):
        return self.get_lasso_server('liberty')

    def sso(self, context):
        lassoServer = self.getLassoServer()
        if not server:
            return self.error_page('Failed building lasso server')
        login = lasso.Login(lassoServer)
        login.initAuthnRequest(lassoServer.providerIds[0], lasso.HTTP_METHOD_REDIRECT)
        login.request.nameIdPolicy = 'federated'
        login.request.forceAuthn = False
        login.request.isPassive = False
        login.request.consent = 'urn:liberty:consent:obtained'

        self.set_sso_relay_state(login, context)

        login.buildAuthnRequestMsg()
        return login.msgUrl

    security.declarePublic('assertionConsumerService')
    def assertionConsumerService(self, context):
        # FIXME: Implement LARES form method.
        lares = None
        request = context.REQUEST
        session = request.SESSION
        query_string = urllib.unquote(request.get('QUERY_STRING'))

        login = lasso.Login(self.getLassoServer())
        if query_string:
            # FIXME: Check Lasso exceptions
            login.initRequest(query_string, lasso.HTTP_METHOD_REDIRECT)
            login.buildRequestMsg()
            soapResponseMessage = self.soap_call(login.msgUrl, login.msgBody)
            if not soapResponseMessage:
                return self.error_page('No SOAP response from identity provider')
            # FIXME: Check Lasso exceptions
            login.processResponseMsg(soapResponseMessage)
        elif lares:
            login.processAuthnResponse(lares)
        else:
            return self.error_page('Missing SSO artifact in HTTP response from the IdP')

        login.acceptSso()

        return self.sso_finish_processing(context, login)

    security.declarePublic('singleLogout')
    def singleLogout(self, context):
        request = context.REQUEST
        response = request.RESPONSE
        session = request.SESSION

        sessionDump = session.get('sessionDump')
        nameIdentifier = session.get('nameIdentifier')
        identityDump = self.federations.getIdentityDump(nameIdentifier)

        query_string = request.get('QUERY_STRING') or ''
        if lasso.isLibertyQuery(query_string):
            next_url, body = self.processLogoutRequestMsg(query_string, sessionDump, identityDump)
            if sessionDump:
                del session['sessionDump']
            if nameIdentifier:
                del session['nameIdentifier']
            context.acl_users.logout(request)
            return next_url
        else:
            logout = lasso.Logout(self.getLassoServer())
            if sessionDump:
                logout.setSessionFromDump(sessionDump)
            if identityDump:
                logout.setIdentityFromDump(identityDump)
            # FIXME: Check Lasso exceptions
            logout.initRequest(None, lasso.HTTP_METHOD_REDIRECT)
            logout.buildRequestMsg()
            return logout.msgUrl

    security.declarePublic('singleLogoutReturn')
    def singleLogoutReturn(self, context):
        request = context.REQUEST
        response = request.RESPONSE
        session = request.SESSION

        query_string = request.get('QUERY_STRING') or ''
        sessionDump = session.get('sessionDump')
        nameIdentifier = session.get('nameIdentifier')
        identityDump = self.federations.getIdentityDump(nameIdentifier)

        logout = lasso.Logout(self.getLassoServer())
        if sessionDump:
            logout.setSessionFromDump(sessionDump)
        if identityDump:
            logout.setIdentityFromDump(identityDump)
        try:
            logout.processResponseMsg(query_string)
        except lasso.Error, error:
            if error[0] != lasso.PROFILE_ERROR_SESSION_NOT_FOUND and \
                    error[0] != lasso.DS_ERROR_INVALID_SIGNATURE:
                raise

        if sessionDump:
            del session['sessionDump']
        if nameIdentifier:
            del session['nameIdentifier']
        context.acl_users.logout(request)
        return self.config['root_url']

    def federationTermination(self, context):
        request = context.REQUEST
        session = request.SESSION

        sessionDump = session.get('sessionDump')
        nameIdentifier = session.get('nameIdentifier')
        identityDump = self.federations.getIdentityDump(nameIdentifier)

        query_string = request.get('QUERY_STRING') or ''
        if lasso.isLibertyQuery(query_string):
            next_url, body = self.processFederationTerminationNotificationMsg(
                fedTermRequest, sessionDump, identityDump)
            if sessionDump:
                del session['sessionDump']
            if nameIdentifier:
                del session['nameIdentifier']
            context.acl_users.logout(request)
            return next_url
        else:
            lassoServer = self.getLassoServer()
            fedTerm = lasso.Defederation(lassoServer)
            fedTerm.setSessionFromDump(sessionDump)
            fedTerm.setIdentityFromDump(identityDump)
            fedTerm.initNotification(lassoServer.providerIds[0], lasso.HTTP_METHOD_SOAP)
            fedTerm.buildNotificationMsg()
            soapResponseMessage = self.soap_call(fedTerm.msgUrl, fedTerm.msgBody)
            if not soapResponseMessage:
                return self.error_page('No SOAP response from identity provider')
            self.federations.removeFederation(nameIdentifier)
            del session['nameIdentifier']
            del session['sessionDump']
            return self.config['root_url']

    def processLogoutRequestMsg(self, logoutRequestMessage, sessionDump, identityDump):
        logout = lasso.Logout(self.getLassoServer())
        logout.processRequestMsg(logoutRequestMessage)
        logout.setSessionFromDump(sessionDump)
        logout.setIdentityFromDump(identityDump)
        try:
            logout.validateRequest()
        except lasso.Error, error:
            if error[0] != lasso.PROFILE_ERROR_SESSION_NOT_FOUND:
                raise
        logout.buildResponseMsg()
        return logout.msgUrl, logout.msgBody

    def processFederationTerminationNotificationMsg(self, fedTermRequestMessage, sessionDump, identityDump):
        defederation = lasso.Defederation(self.getLassoServer())
        defederation.processNotificationMsg(fedTermRequestMessage)
        defederation.setSessionFromDump(sessionDump)
        defederation.setIdentityFromDump(identityDump)
        try:
            defederation.validateNotification()
        except lasso.Error, error:
            pass # ignore failure (?)
        return defederation.msgUrl, defederation.msgBody

    def singleLogoutSOAP(self, context):
        request = context.REQUEST
        response = request.RESPONSE
        session = request.SESSION

        sessionDump = session.get('sessionDump')
        nameIdentifier = session.get('nameIdentifier')
        identityDump = self.federations.getIdentityDump(nameIdentifier)

        query_string = request.get('QUERY_STRING') or ''
        if lasso.isLibertyQuery(query_string):
            next_url, body = self.processLogoutRequestMsg(query_string, sessionDump, identityDump)
            if sessionDump:
                del session['sessionDump']
            if nameIdentifier:
                del session['nameIdentifier']
            context.acl_users.logout(request)
            return next_url
        else:
            logout = lasso.Logout(self.getLassoServer())
            logout.setSessionFromDump(sessionDump)
            logout.setIdentityFromDump(identityDump)
            logout.initRequest(None, lasso.HTTP_METHOD_SOAP)
            logout.buildRequestMsg()
            soapResponseMessage = self.soap_call(logout.msgUrl, logout.msgBody)
            if not soapResponseMessage:
                return self.error_page('No SOAP response from identity provider')
            logout.processResponseMsg(soapResponseMessage)
            del session['sessionDump']
            del session['nameIdentifier']
            context.acl_users.logout(request)
            return self.config['root_url']

    def removeLibertyDataFromSession(self, session):
        contents = session[1]
        del contents['sessionDump']
        del contents['nameIdentifier']

    def soapEndpoint(self, session_data, soapRequestMessage):
        request_type = lasso.getRequestTypeFromSoapMsg(soapRequestMessage)

        if request_type == lasso.REQUEST_TYPE_LOGOUT:
            logout = lasso.Logout(self.getLassoServer())
            logout.processRequestMsg(soapRequestMessage)
            nameIdentifier = logout.nameIdentifier.content
            identityDump = self.federations.getIdentityDump(nameIdentifier)
            logout.setIdentityFromDump(identityDump)
            sessionDump = self.getSessionDumpFromSessionData(session_data)
            logout.setSessionFromDump(sessionDump)
            try:
                logout.validateRequest()
            except lasso.Error, error:
                if error[0] != lasso.PROFILE_ERROR_SESSION_NOT_FOUND:
                    raise
            else:
                session = self.getSessionFromNameIdentifier(session_data, nameIdentifier)
                if session:
                    self.removeLibertyDataFromSession(session_data, nameIdentifier)
                    session.invalidate()
            logout.buildResponseMsg()
            return '200', logout.msgBody

        elif request_type == lasso.REQUEST_TYPE_DEFEDERATION:
            defederation = lasso.Defederation(self.getLassoServer())
            defederation.processNotificationMsg(soapRequestMessage)
            nameIdentifier = defederation.nameIdentifier.content
            identityDump = self.federations.getIdentityDump(nameIdentifier)
            defederation.setIdentityFromDump(identityDump)
            try:
                defederation.validateNotification()
            except lasso.Error, error:
                pass
            else:
                self.federations.removeFederation(nameIdentifier)
                session = self.getSessionFromNameIdentifier(session_data, nameIdentifier)
                if session:
                    self.removeLibertyDataFromSession(session)
            return '204', None
 
        return '500', None

InitializeClass(Liberty)
