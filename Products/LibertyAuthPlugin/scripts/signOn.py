libauth = context.acl_users.%(libplugin_id)s.libauth
next_url = libauth.signOn(context)
context.REQUEST.RESPONSE.redirect(next_url)
