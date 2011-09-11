# Zope
from Globals import InitializeClass, PersistentMapping
from OFS.SimpleItem import SimpleItem

class Federations(SimpleItem):
    def __init__(self):
        self.federations = PersistentMapping()

    def getUserId(self, nameIdentifier):
        return self.federations.get(nameIdentifier, {}).get('user_id')

    def getIdentityDump(self, nameIdentifier):
        return self.federations.get(nameIdentifier, {}).get('identity_dump')

    def setFederation(self, nameIdentifier, userId, identityDump):
        self.federations[nameIdentifier] = {'user_id': userId, 'identity_dump': identityDump}

    def removeFederation(self, nameIdentifier):
        if self.federations.has_key(nameIdentifier):
            del self.federations[nameIdentifier]

InitializeClass(Federations)
