saml = context.acl_users.%(libplugin_id)s.libauth.saml
next_url = saml.singleLogout(context)
context.REQUEST.RESPONSE.redirect(next_url)
