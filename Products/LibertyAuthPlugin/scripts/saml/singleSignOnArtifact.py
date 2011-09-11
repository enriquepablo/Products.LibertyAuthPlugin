saml = context.acl_users.%(libplugin_id)s.libauth.saml
next_url = saml.singleSignOnArtifact(context)
context.REQUEST.RESPONSE.redirect(next_url)
