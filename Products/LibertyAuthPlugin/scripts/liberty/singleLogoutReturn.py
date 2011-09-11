liberty = context.acl_users.%(libplugin_id)s.libauth.liberty
next_url = liberty.singleLogoutReturn(context)
context.REQUEST.RESPONSE.redirect(next_url)
