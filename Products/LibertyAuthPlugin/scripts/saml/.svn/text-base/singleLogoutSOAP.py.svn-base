saml = context.acl_users.%(libplugin_id)s.libauth.saml
soapRequestMessage = context.REQUEST.stdin.read()
status, soapResponseMessage = saml.singleLogoutSOAP(container.temp_folder.session_data, soapRequestMessage)
context.REQUEST.RESPONSE.setStatus(status)
if status == 200:
    context.REQUEST.RESPONSE.write(soapResponseMessage)
