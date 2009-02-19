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
    def verifyToken(self, token):
        url = 'http://reptilian.habets.pp.se:8080/auth/0/?token=%s' % (token)
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
        key = raw_input("")
        if len(key) < 44:
            return "FAIL"
        keyid = key[-44:][:12]
        try:
            try:
                for line in open(os.path.join(pwd.getpwnam(user)[5],
                                              ".yubikeys")):
                    fkey, url = line.split(None, 1)
                    if fkey == keyid or fkey == dvorak2qwerty(keyid):
                        break
                else:
                    raise self.ErrBase("Unauthorized yubikey")
            except:
                raise self.ErrBase("Unauthorized yubikey")

            self.verifyToken(key)
            return "OK"
        except self.ErrUsername, e:
            return "FAIL"
        except self.ErrNotice, e:
            return str(e)
        except self.ErrBase, e:
            return "FAIL"
        except:
            return "FAIL"

def main():
    y = Authenticator()
    res = y.run()
    print res

main()
