from OFS.Folder import Folder
from OFS.DTMLDocument import DTMLDocument
from OFS.Image import File

from Products.PythonScripts.PythonScript import PythonScript

from zLOG import LOG, INFO, ERROR, WARNING

class CustomError(Exception):
    pass

class CustomFolder:
    def __init__(self, config):
        self.config = config
        self.dtml_home = config['plugin_home'] + '/dtml'
        self.scripts_home = config['plugin_home'] + '/scripts'

    def register_dtml_object(self, object_name):
        file_path = '%s/%s.dtml' % (self.dtml_home, object_name)
        try:
            content = open(file_path).read()
            if not content:
                raise CustomError('Empty file : %s' % file_path)
            dtml_ob = DTMLDocument(content, __name__ = object_name)
            self.folder._setObject(object_name, dtml_ob)
        except Exception, err:
            LOG('', ERROR, err)

    def register_script_object(self, object_name):
        file_path = '%s/%s.py' % (self.scripts_home, object_name)
        try:
            content = open(file_path).read()
            if not content:
                raise CustomError('Empty file : %s' % file_path)
            content = content % {'libplugin_id' : self.config['id']}
            script_ob = PythonScript(object_name)
            script_ob.write(content)
            self.folder._setObject(object_name, script_ob)
        except Exception, err:
            LOG('', ERROR, err)

    def register_file_object(self, file_path, content_type, file_name=None):
        if not file_path or not file_path.startswith('/'):
            return
        if file_name is None:
            file_name = file_path.split('/')[-1]
        try:
            content = open(file_path).read()
            if not content:
                raise CustomError('Empty file : %s' % file_path)
            file_ob = File(file_name, None, content, content_type)
            if self.folder.hasObject(file_name):
                self.folder._delObject(file_name)
            self.folder._setObject(file_name, file_ob)
        except Exception, err:
            LOG('', ERROR, err)

class LibAuthFolder(CustomFolder):
    def __init__(self, parent_folder, config):
        if parent_folder.hasObject('libauth'):
            parent_folder._delObject('libauth')

        self.folder = Folder('libauth')
        parent_folder._setObject('libauth', self.folder)

        CustomFolder.__init__(self, config)

        self.liberty = LibertyFolder(self.folder, config)
        self.saml = SamlFolder(self.folder, config)

    def setup(self):
        self.set_urls()
        self.set_files()

    def set_urls(self):
        self.register_script_object('signOn')
        self.register_script_object('signOut')
        self.register_dtml_object('chooseFederationMethod')
        self.register_dtml_object('registerUserToken')
        self.register_dtml_object('registerFederatedAccount')
        self.register_script_object('completeUserTokenRegistration')
        self.register_script_object('completeUserFederatedAccount')
        self.liberty.set_urls()
        self.saml.set_urls()

    def set_files(self):
        self.register_file_object(self.config['publickey_path'], 'text/plain')
        self.liberty.set_files()
        self.saml.set_files()


class LibertyFolder(CustomFolder):
    def __init__(self, parent_folder, config):
        if parent_folder.hasObject('liberty'):
            parent_folder._delObject('liberty')

        self.folder = Folder('liberty')
        parent_folder._setObject('liberty', self.folder)

        CustomFolder.__init__(self, config)

        self.scripts_home = self.scripts_home + '/liberty'

    def set_urls(self):
        self.register_script_object('soapEndpoint')
        self.register_script_object('assertionConsumerService')
        self.register_script_object('singleLogout')
        self.register_script_object('singleLogoutReturn')
        self.register_script_object('federationTermination')

    def set_files(self):
        self.register_file_object(self.config['liberty']['metadata_path'], 'text/xml')

class SamlFolder(CustomFolder):
    def __init__(self, parent_folder, config):
        if parent_folder.hasObject('saml'):
            parent_folder._delObject('saml')

        self.folder = Folder('saml')
        parent_folder._setObject('saml', self.folder)

        CustomFolder.__init__(self, config)

        self.scripts_home = self.scripts_home + '/saml'

    def set_urls(self):
        self.register_script_object('singleSignOnArtifact')
        self.register_script_object('singleLogoutSP')
        self.register_script_object('singleLogoutReturn')
        self.register_script_object('singleLogoutSOAP')
        self.register_script_object('singleLogout')
        self.register_script_object('manageNameId')

    def set_files(self):
        self.register_file_object(self.config['saml']['metadata_path'], 'text/xml',
                                  self.config['saml']['metadata_url'].split('/')[-1])

