#!/usr/local/bin/python

import sys
import urllib

#usermap = {"vvvvvvvvvvvv": ('localuser1', 'localuser2')}
usermap = {"gfrklhlghlrt": ('marvin')}

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
        url = 'http://localhost:8080/auth/0/?token=%s' % (token)
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
