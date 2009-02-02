#!/usr/local/bin/python

import yubico.auth
import sys

#usermap = {"vvvvvvvvvvvv": ('localuser1', 'localuser2')}
usermap = {"gfrklhlghlrt": ('marvin')}

def dvorak2qwerty(s):
    dvorak = "`1234567890[]',.pyfgcrl/=aoeuidhtns-\\<;qjkxbmwvz"
    qwerty_us = "`1234567890-=qwertyuiop[]asdfghjkl;'\\<zxcvbnm,./"
    m = {}
    for i in range(len(dvorak)):
        m[dvorak[i]] = qwerty_us[i]
    return ''.join([m[x] for x in s])

def test():
    me = '1'
    y = yubico.auth.yubico(me)
    user = raw_input("")
    key = raw_input("")
    try:
        if not user in usermap[key[:12]]:
            raise "NOOOO"

        if "status=OK" != y.verify(key):
            raise "NOOO"
    except:
        key = dvorak2qwerty(key)
        try:
            if not user in usermap[key[:12]]:
                raise "NOOOO"
            if "status=OK" != y.verify(key):
                raise "NOOO"
        except:
            return "FAIL\n"
            return "NOTICE Auth server says: %s" % ("FIXME")
    return "OK"

def main():
    res = test()
    print res

main()
