liberty = context.acl_users.%(libplugin_id)s.libauth.liberty
soapRequestMessage = context.REQUEST.stdin.read()
status, soapResponseMessage = liberty.soapEndpoint(container.temp_folder.session_data, soapRequestMessage)
context.REQUEST.RESPONSE.setStatus(status)
if status == 200:
    context.REQUEST.RESPONSE.write(soapResponseMessage)
