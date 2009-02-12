#!/usr/local/bin/python

import sys
import urllib

usermap = {
	"gfrklhlghlrt": ('marvin', 'thompa'),
	"bbjfbfhlbhvi": ('marvin', 'thompa'),
	}

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
    class ErrBadPassword(Exception):
        pass
    class ErrNotice(Exception):
        pass
    def verifyToken(self, token):
        url = 'http://reptilian.habets.pp.se:8080/auth/0/?token=%s' % (token)
        res = urllib.urlopen(url)
        rs = res.read()
        if rs == "OK\n":
            return True
        if rs == "FAIL\n":
            raise self.ErrBadPassword()
        raise self.ErrNotice(rs)

    def run(self):
        user = raw_input("")
        key = raw_input("")
        if len(key) < 44:
            return "FAIL"
        try:
            if not user in usermap[key[:12]]:
                raise self.ErrBase("User not in map")

            self.verifyToken(key)
        except self.ErrUsername, e:
            return "FAIL\n"
        except self.ErrNotice, e:
            return str(e)
        except:
            try:
                pw = key[:-44]
                key = key[-44:]
                key = pw + dvorak2qwerty(key)
                self.verifyToken(key)
            except self.ErrNotice, e:
                return str(e)
            except self.ErrBase, e:
                return "FAIL\n"
        return "OK"

def main():
    y = Authenticator()
    res = y.run()
    print res

main()
