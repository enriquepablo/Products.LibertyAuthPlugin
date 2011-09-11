from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin

from LibertyAuthPlugin import LibertyAuthPlugin, addForm, addFunction

def initialize(registrar):

    registerMultiPlugin(LibertyAuthPlugin.meta_type)

    registrar.registerClass(
        LibertyAuthPlugin, 
        constructors = (addForm, addFunction),
        icon = 'www/lasso.png'
        )

    registrar.registerHelp()
