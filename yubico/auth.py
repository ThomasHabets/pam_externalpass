'''The Python yubico.auth module.'''

import socket
#import socket.ssl
import urllib
import os, sys
import re
import string
from yerror import responseError

DEBUG = True

class yubico:
    
    def __init__( self, id, key=None ):
        self.client_id = id
        self.user_key = key
        self.response = None
        if self.client_id and self.user_key:
            self.verify( self.user_key, self.client_id )

    def verify( self, otp, id=None):
        '''Verify an Yubikey OTP token. Returns the value of the response variable "status"

        req = yubico.auth.verify( token, id )
        req
        >> NO_SUCH_CLIENT

        Upon an error, you should use the yubico.auth.response'''
        if id is None:
            id = self.client_id
        fullurl = "http://api.yubico.com/wsapi/verify?id=%s&otp=%s" % \
            ( id, otp )
        res = urllib.urlopen( fullurl )
        self.response = res.read()
        if not re.search( r'status=([a-zA-Z0-9_]+)', self.response ):
            raise responseError, self.response

        return re.search(r'status=([a-zA-Z0-9_]+)', self.response).group(0)
