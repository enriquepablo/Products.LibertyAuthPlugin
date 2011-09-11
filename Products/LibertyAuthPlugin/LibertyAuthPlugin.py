import os
import random
import base64

# Zope
from AccessControl import ClassSecurityInfo
from Acquisition import aq_parent
from Globals import InitializeClass, DTMLFile
from OFS.SimpleItem import SimpleItem
from zLOG import LOG, INFO, ERROR, WARNING

# Zope products
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin, \
    IAuthenticationPlugin, IChallengePlugin
from Products.CMFCore.utils import getToolByName
from Products.MailHost.MailHost import MailHostError

# Local
from LibAuthFolders import LibAuthFolder
from Federations import Federations
from UserTokens import UserTokens
import LibAuth

class CustomError(Exception):
    pass


# Plugin initialisation form and function

addForm = DTMLFile('dtml/addLibertyAuthPlugin', globals())

def addFunction(dispatcher, id, organisation_name, generateMetadataAndKeys=None, REQUEST=None):
    """
    Create a new Liberty Auth Plugin.
    """
    # Names with ' ' or '-' are bad for python
    id = id.replace(' ', '_').replace('-', '_')
    dest = dispatcher.Destination()
    root = aq_parent(dest)
    root_url = root.absolute_url()

    instance_home = os.environ.get('INSTANCE_HOME')
    plugin_home = instance_home + '/Products/LibertyAuthPlugin'

    config = setup_config(id, plugin_home, root_url, organisation_name, generateMetadataAndKeys)

    # setup liberty plugin object
    plugin = LibertyAuthPlugin(config)
    dest._setObject(id, plugin)

    # setup public urls
    folder = LibAuthFolder(root, config)
    folder.setup()
    plugin.folder = folder

    if REQUEST is not None:
        dispatcher.manage_main(dispatcher, REQUEST)

def setup_config(id, plugin_home, root_url, organisation_name, generateMetadataAndKeys):
    plugin_instance_home = '%s/config/%s' % (plugin_home, id)
    config = {
        'id': id,
        'plugin_home': plugin_home,
        'plugin_instance_home': plugin_instance_home,
        'root_url': root_url,
        'organisation_name': organisation_name,
        'generateMetadataAndKeys': generateMetadataAndKeys,
        'providers_home': '%s/providers' % plugin_instance_home,
        'privatekey_path': '%s/privatekey.pem' % plugin_instance_home,
        'publickey_path': '%s/publickey.pem' % plugin_instance_home,
    }
    libauth_url = '%s/libauth' % root_url
    config['libauth'] = {
        'libauth_url': libauth_url
    }
    liberty_url = '%s/liberty' % libauth_url
    config['liberty'] = {
        'liberty_url': liberty_url,
        'metadata_url': '%s/metadata.xml' % liberty_url,
        'publickey_url': '%s/publickey.pem' % liberty_url,
        'metadata_path': '%s/metadata.xml' % plugin_instance_home,
    }
    saml_url = '%s/saml' % libauth_url
    config['saml'] = {
        'saml_url': saml_url,
        'metadata_url': '%s/metadata.xml' % saml_url,
        'publickey_url': '%s/publickey.pem' % saml_url,
        'metadata_path': '%s/saml2_metadata.xml' % plugin_instance_home,
    }
    return config

class LibertyAuthPlugin(BasePlugin, SimpleItem):
    """
    LibertyAuthPlugin product class
    """
    meta_type = 'LibertyAuthPlugin'

    # Administration menu tabs
    manage_options = BasePlugin.manage_options + (
        {'label' : 'Liberty Provider',
         'action' : 'editForm',
         'help' : ('LibertyAuthPlugin', 'edit.txt')
        },
        {'label' : 'Remote Providers',
         'action' : 'editLibertyProvidersForm',
        },
        {'label' : 'Liberty tokens',
         'action' : 'editLibertyTokensForm',
         'help' : ('LibertyAuthPlugin', 'edit.txt')
        },
    )

    security = ClassSecurityInfo()

    security.declareProtected('View management screens', 'editForm')
    editForm = DTMLFile('dtml/editLibertyAuthPluginForm', globals())

    security.declareProtected('View management screens', 'editLibertyProvidersForm')
    editLibertyProvidersForm = DTMLFile('dtml/editLibertyProvidersForm', globals())

    security.declareProtected('View Remote Provider screen', 'viewRemoteProviderForm')
    viewRemoteProviderForm = DTMLFile('dtml/viewRemoteProviderForm', globals())

    security.declareProtected('Edit Remote Provider screen', 'editRemoteProviderForm')
    editRemoteProviderForm = DTMLFile('dtml/editRemoteProviderForm', globals())

    security.declareProtected('Edit liberty tokens screen.', 'editLibertyTokensForm')
    editLibertyTokensForm = DTMLFile('dtml/editLibertyTokensForm', globals())

    def __init__(self, config):
        self.config = config
        # The "id" attribute is *required* for PAS plugin registration
        self.id = self.config['id']

        # This email address is configurable from admin interface
        self._emailSender = 'admin@yourploneportal'
        # This email content is configurable from admin interface
        # The %s variable is replaced when used
        self._mailContent = """This is an email about user token federation.
To initiate a single sign on with token registration, go to this url :
%s"""

        try:
            os.makedirs(self.config['plugin_instance_home'])
        except OSError, err:
            LOG('', WARNING, err)

        # The following classes need to be instantiated within this main class to be part of Zope
        # infrastructure, including persistence mechanisms
        self.federations = Federations()
        self.userTokens = UserTokens()
        self.libauth = LibAuth.LibAuth(self)

    def save_uploaded_file(self, up_file, path):
        try:
            open(path, 'w').write(up_file.read())
        except OSError, err:
            LOG('', ERROR, err)

    def save_form_data(self, data, path):
        try:
            open(path, 'w').write(data)
        except OSError, err:
            LOG('', ERROR, err)


    security.declareProtected('Change LibertyAuthPlugin', 'editLibertyAuthPlugin')
    def editLibertyAuthPlugin(self, REQUEST=None):
        """
        Modify Liberty configuration
        """
        if REQUEST is None:
            LOG('', ERROR, 'No request (how could this happen ??)')
            return

        # FIXME: Check incoming parameters

        saml_metadata_content = REQUEST.form['samlMetadata']
        if saml_metadata_content:
            self.save_form_data(saml_metadata_content, self.config['saml']['metadata_path'])

        saml_metadata_file = REQUEST.form.get('samlMetadataFile')
        if saml_metadata_file:
            self.save_uploaded_file(saml_metadata_file, self.config['saml']['metadata_path'])

        liberty_metadata_content = REQUEST.form['metadata']
        if liberty_metadata_content:
            self.save_form_data(liberty_metadata_content, self.config['liberty']['metadata_path'])

        liberty_metadata_file = REQUEST.form.get('metadataFile')
        if liberty_metadata_file:
            self.save_uploaded_file(liberty_metadata_file, self.config['liberty']['metadata_path'])

        privatekey_file = REQUEST.form.get('privatekeyFile')
        if privatekey_file:
            self.save_uploaded_file(privatekey_file, self.config['publickey_path'])

        publickey_file = REQUEST.form.get('publickeyFile')
        if publickey_file:
            self.save_uploaded_file(privatekey_file, self.config['publickey_path'])

        # Update metadata files registered as Zope files
        self.folder.set_files()

        return self.editForm(self,
                             REQUEST,
                             manage_tabs_message = 'Liberty provider configuration updated.')

    security.declareProtected('Add Remote Provider', 'addRemoteProvider')
    def addRemoteProvider(self, name, metadata, publickey, REQUEST=None):
        """
        Add a Liberty Remote Provider.
        """
        if REQUEST is None:
            LOG('', ERROR, 'No request (how could this happen ??)')
            return

        try:
            if not name:
                raise CustomError('You must provide a name')
            if not metadata:
                raise CustomError('You must provide a metadata file')

            provider_home = '%s/%s' % (self.config['providers_home'], name.replace(' ', '_'))
            try:
                os.makedirs(provider_home)
            except OSError, err:
                LOG('', ERROR, err)
                raise CustomError('Failed writing files to disk')

            metadata_content = metadata.read()
            metadata_path = '%s/metadata.xml' % provider_home
            try:
                open(metadata_path, 'w').write(metadata_content)
            except IOError, err:
                LOG('', ERROR, err)
                raise CustomError('Failed writing metadata to disk')

            if publickey:
                publickey_content = publickey.read()
                publickey_path = '%s/publickey.pem' % provider_home
                try:
                    open(publickey_path, 'w').write(publickey_content)
                except IOError:
                    LOG('', ERROR, err)
                    raise CustomError('Failed writing public_key to disk')
        except CustomError, err:
            result_msg = 'Error : %s.' % e
        else:
            result_msg = 'Remote Provider added.'

        return self.editLibertyProvidersForm(self, REQUEST, manage_tabs_message = result_msg)

    security.declareProtected('View Remote Provider Settings', 'viewRemoteProvider')
    def viewRemoteProvider(self, name, REQUEST=None):
        """
        View remote provider metadata and public key
        """
        if REQUEST is None:
            LOG('', ERROR, 'No request (how could this happen ??)')
            return

        if not name:
            LOG('', ERROR, 'No name parameter')
            return

        provider = None
        providers = self.libauth.get_identity_providers()
        for p in providers:
            if p['name'] == name:
                provider = p
                break
        if provider:
            try:
                metadata = open(provider['metadata_path']).read()
            except IOError, err:
                LOG('', ERROR, err)
                metadata = 'Failed reading metadata file.'

            if not provider['publickey_path']:
                publickey = 'No public key file. Public key should be included in metadata.'
            else:
                try:
                    publickey = open(provider['publickey_path']).read()
                except IOError, err:
                    publickey = 'Failed reading public key file.'

            return self.viewRemoteProviderForm(self,
                                               REQUEST,
                                               name = name,
                                               metadata = metadata,
                                               publickey = publickey)

    security.declareProtected('edit Remote Provider Settings', 'editRemoteProvider')
    def editRemoteProvider(self, name, metadata=None, publickey=None, REQUEST=None):
        """
        Edit remote provider metadata and public key
        """
        if REQUEST is None:
            LOG('', ERROR, 'No request (how could this happen ??)')
            return

        if not name:
            LOG('', ERROR, 'No name parameter')
            return

        try:
            provider = None
            providers = self.libauth.get_identity_providers()
            for p in providers:
                if p['name'] == name:
                    provider = p
                    break
            if not provider:
                raise CustomError('Provider not found')

            if metadata:
                LOG('', INFO, 'Update of metadata')
                metadata_content = REQUEST.form['metadata'].read()
                try:
                    open(provider['metadata'], 'w').write(metadata_content)
                except IOError, err:
                    LOG('', ERROR, err)
                    raise CustomError('Failed writing metadata to disk')

            if publickey:
                LOG('', INFO, 'Update of public key')
                publickey_content = REQUEST.form['publickey'].read()
                try:
                    open(provider['publickey'], 'w').write(publickey_content)
                except IOError, err:
                    LOG('', ERROR, err)
                    raise CustomError('Failed writing public_key to disk')
        except CustomError, err:
            result_msg = 'Error : %s.' % e
        else:
            result_msg = 'Liberty Remote Provider updated.'

        return self.editLibertyProvidersForm(self, REQUEST, manage_tabs_message = result_msg)

    def removeRemoteProvider(self, name, REQUEST=None):
        """
        Remove a Liberty Remote Provider
        """
        if REQUEST is None:
            LOG('', ERROR, 'No request (how could this happen ??)')
            return

        if not name:
            LOG('', ERROR, 'No name parameter')
            return

        try:
            provider = None
            providers = self.libauth.get_identity_providers()
            for p in providers:
                if p['name'] == name:
                    provider_home = '%s/%s' % (self.config['providers_home'], name)
                    files_to_remove = ('%s/metadata.xml' % provider_home,
                                       '%s/publickey.pem' % provider_home)
                    try:
                        for f in files_to_remove:
                            if os.path.exists(f):
                                os.remove(f)
                        if os.path.exists(provider_home):
                            os.rmdir(provider_home)
                    except OSError, err:
                        LOG('', ERROR, err)
                        raise CustomError('Failed deleting provider configuration')
                    break
        except CustomError, err:
            result_msg = 'Error : %s.' % e
        else:
            result_msg = 'Remote Provider deleted.'

        return self.editLibertyProvidersForm(self, REQUEST, manage_tabs_message = result_msg)

    security.declareProtected('Edit liberty tokens', 'editLibertyTokens')
    def editLibertyTokens(self, emailSender, mailContent, REQUEST=None):
        """
        Changes Liberty user token mail sending informations.
        """
        if REQUEST is None:
            LOG('', ERROR, 'No request (how could this happen ??)')
            return

        # FIXME: Check incoming parameters

        self._emailSender = emailSender
        self._mailContent = mailContent

        return self.editLibertyTokensForm(self,
                                          REQUEST,
                                          manage_tabs_message = 'Liberty mail information updated.')

    def getUserTokens(self):
        return self.userTokens.getUserTokensList()

    def addUserToken(self, userId, email=None, REQUEST=None):
        """
        ...
        """
        if REQUEST is None:
            LOG('', ERROR, 'No request (how could this happen ??)')
            return

        if not userId:
            LOG('', ERROR, 'No userId parameter')
            return

        try:
            userToken = self.userTokens.getUserToken(userId)
            if not userToken:
                userToken = self.userTokens.generateToken(userId)
            else:
                LOG('', WARNING, 'User %s already has a token' % userId)

            if not email:
                raise CustomError("Generated token but can't send it by email because not address is provided")

            portal_url = getToolByName(self, 'portal_url')
            mailhost = portal_url.MailHost
            
            register_token_url = '%s/%s' % (self.config['libauth']['libauth_url'],
                'completeUserTokenRegistration?userToken=%s' % userToken)
            register_token_url_base64 = base64.encodestring(register_token_url)
            sso_url = '%s/%s' % (self.config['libauth']['libauth_url'],
                'signOn?RelayState=%s' % register_token_url_base64)
            mMsg = self._mailContent % sso_url
            mTo = email
            mFrom = self._emailSender
            mSubj = 'User registration'

            try:
                mailhost.send(mMsg, mTo, mFrom, mSubj)
            except MailHostError, err:
                raise CustomError('No mail server configured.\nIn your site instance administration, select "Mailhost" and configure it properly.')

            LOG('LibAuthPlugin addUserToken :', INFO, 'sent token %s to email : %s' % (userToken, email))
        except CustomError, e:
            result_msg = 'Error : %s.' % e
        else:
            result_msg = 'Created user token and sent email to user %s.' % userId

        return self.editLibertyTokensForm(self, REQUEST, manage_tabs_message = result_msg)

    def removeUserToken(self, userToken, REQUEST=None):
        """
        Remove user token.
        """
        if REQUEST is None:
            LOG('', ERROR, 'No request (how could this happen ??)')
            return

        if not userToken:
            LOG('', ERROR, 'No userToken parameter')
            return

        self.userTokens.removeToken(userToken)

        return self.editForm(self, REQUEST, manage_tabs_message = 'User token removed.')


    def getLibertyMetadata(self):
        """Return ID-FF metadata"""
        try:
            return open(self.config['liberty']['metadata_path']).read()
        except:
            return ''

    def getLibertyMetadataUrl(self):
        """Return provider metadata URL"""
        return self.config['liberty']['metadata_url']

    def getLibertyMetadataPath(self):
        """Return provider metadata file path"""
        return self.config['liberty']['metadata_path']

    def getSamlMetadata(self):
        """Return SAML 2.0 metadata"""
        try:
            return open(self.config['saml']['metadata_path']).read()
        except:
            return ''

    def getSamlMetadataUrl(self):
        """Return metadata URL"""
        return self.config['saml']['metadata_url']

    def getSamlMetadataPath(self):
        """Return metadata file path"""
        return self.config['saml']['metadata_path']

    def getPublicKey(self):
        """Return public key"""
        try:
            return open(self.config['publickey_path']).read()
        except:
            return ''

    def getPublicKeyUrl(self):
        """Return public key URL"""
        return self.config['liberty']['publickey_url']

    def getPublicKeyPath(self):
        """Return public key file path"""
        return self.config['publickey_path']

    def getPrivateKeyPath(self):
        """Return private key file path"""
        return self.config['privatekey_path']

    def getMailContent(self):
        """Return mail content"""
        return self._mailContent

    def getEmailSender(self):
        """Return email sender"""
        return self._emailSender

    def manage_beforeDelete(self, item, container):
        """Delete all configuration. This method is called when deleting a plugin instance."""
        LOG('', INFO, 'Deleting all configuration')

        files_to_remove = []
        dirs_to_remove = []
        providers_home = self.config['providers_home']

        # Remove remote providers settings
        try:
            providers = os.listdir(providers_home)
        except OSError:
            pass
        else:
            for p in providers:
                files_to_remove.append('%s/%s/metadata.xml' % (providers_home, p))
                files_to_remove.append('%s/%s/publickey.pem' % (providers_home, p))
                dirs_to_remove.append('%s/%s' % (providers_home, p))
            dirs_to_remove.append(providers_home)

        # Remove provider settings
        files_to_remove.append(self.config['liberty']['metadata_path'])
        files_to_remove.append(self.config['saml']['metadata_path'])
        files_to_remove.append(self.config['privatekey_path'])
        files_to_remove.append(self.config['publickey_path'])
        dirs_to_remove.append(self.config['plugin_instance_home'])

        for f in files_to_remove:
            if os.path.exists(f):
                os.remove(f)
        for d in dirs_to_remove:
            if os.path.exists(d):
                os.rmdir(d)


    # Declare available PAS interfaces

    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        nameIdentifier = request.SESSION.get('nameIdentifier')
        if nameIdentifier is None:
            return {}

        return {'nameIdentifier': nameIdentifier}

    security.declarePrivate('authenticateCredentials')
    def authenticateCredentials(self, credentials):
        nameIdentifier = credentials.get('nameIdentifier')
        if nameIdentifier is None:
            return (None, None)

        userId = self.federations.getUserId(nameIdentifier)
        if userId is None:
            return (None, None)

        return (userId, userId)

    security.declarePrivate('challenge')
    def challenge(self, request, response, **kw):
        return 1


# Set PAS interfaces implemented by this plugin

classImplements(LibertyAuthPlugin, IExtractionPlugin, IAuthenticationPlugin, IChallengePlugin)
InitializeClass(LibertyAuthPlugin)
