#!/usr/local/bin/python

import sys
import urllib
import os.path
import pwd

if False:
    from M2Crypto import Rand, SSL, httpslib

    def get_https(host, url, port=443, certs=('cacert.crt',)):
        ctx = SSL.Context()
        for cert in certs:
            if ctx.load_verify_locations(cert) != 1:
                raise Exception('CA certificates not loaded')
        ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9)
        h = httpslib.HTTPSConnection(host, port, ssl_context=ctx)
        h.putrequest('GET', '/')
        h.endheaders()
        resp = h.getresponse()
        return resp

def dvorak2qwerty(s):
    dvorak = "`1234567890[]',.pyfgcrl/=aoeuidhtns-\\<;qjkxbmwvz"
    qwerty_us = "`1234567890-=qwertyuiop[]asdfghjkl;'\\<zxcvbnm,./"
    m = {}
    for i in range(len(dvorak)):
        m[dvorak[i]] = qwerty_us[i]
    return ''.join([m[x] for x in s])

class Authenticator:
    class ErrBase(Exception):
        pass
    class ErrUsername(ErrBase):
        pass
    class ErrBadPassword(ErrBase):
        pass
    class ErrNotice(ErrBase):
        pass
    def verifyToken(self, token, url):
        url = url % ({'token': token})
        try:
            res = urllib.urlopen(url)
        except IOError, e:
            raise self.ErrBadPassword()

        rs = res.read()
        if rs == "OK":
            return True
        if rs == "FAIL":
            raise self.ErrBadPassword()
        raise self.ErrNotice(rs)

    def run(self):
        user = raw_input("")
        token = raw_input("")
        if len(token) < 44:
            return "FAIL"
        keyid = token[-44:][:12]
        try:
            for line in open(os.path.join(pwd.getpwnam(user)[5],
                                          ".yubikeys")):
                key, url = line.split(None, 1)
                if key == keyid or key == dvorak2qwerty(keyid):
                    # FIXME: handle same key, different authserver
                    self.verifyToken(token, url)
                    return "OK"
            raise self.ErrBase("Yubikey not listed as authorized")

        except self.ErrUsername, e:
            # FIXME: log
            return "FAIL"

        except self.ErrNotice, e:
            # FIXME: log
            return str(e)

        except self.ErrBase, e:
            # FIXME: log
            return "FAIL"

        except:
            # FIXME: log
            return "FAIL"

def main():
    y = Authenticator()
    res = y.run()
    print res

main()
