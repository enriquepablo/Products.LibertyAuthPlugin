# Zope
from Globals import InitializeClass, PersistentMapping
from OFS.SimpleItem import SimpleItem
from zLOG import LOG, WARNING

class UserTokens(SimpleItem):
    def __init__(self):
        self.user_tokens = PersistentMapping()

    def generateToken(self, userId):
        import random
        token = str(random.random()).split('.')[1]
        self.user_tokens[token] = userId
        return token

    def getUserId(self, userToken):
        if self.user_tokens.has_key(token):
            return self.user_tokens[token]
        return None

    def getUserToken(self, userId):
        for token, user_id in self.user_tokens.iteritems():
            if user_id == userId:
                return token
        return None

    def getUserTokensList(self):
        tokens = []
        for token, user_id in self.user_tokens.iteritems():
            tokens.append({'userId' : user_id, 'userToken' : token})
        return tokens

    def removeToken(self, userToken):
        """
        Remove user token.
        """
        if self.user_tokens.has_key(userToken):
            del self.user_tokens[userToken]
        else:
            LOG('', WARNING, 'Tried to remove unexisting token : %s' % userToken)

InitializeClass(UserTokens)
