liberty = context.acl_users.%(libplugin_id)s.libauth.liberty
next_url = liberty.federationTermination(context)
context.REQUEST.RESPONSE.redirect(next_url)
