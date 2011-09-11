libauth = context.acl_users.%(libplugin_id)s.libauth
next_url = libauth.completeUserTokenRegistration(context)
context.REQUEST.RESPONSE.redirect(next_url)
