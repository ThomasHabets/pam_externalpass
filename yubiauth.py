#!/usr/local/bin/python

import sys
import os.path
import pwd
import os
import re
import logging
import logging.handlers

logger = logging.getLogger('yubiauth.py')
#logger.setLevel(logging.DEBUG)
try:
    handler = logging.handlers.SysLogHandler("/dev/log")
except:
    handler = logging.handlers.DatagramHandler('127.0.0.1', 514)
handler.setFormatter(logging.Formatter("%(name)s[%(process)d] %(message)s"))
logger.addHandler(handler)

userconf_envname = "PAM_EXTERNALPASS_USERCONF"
maxConfFileSize = 1000000 # max ~/.yubikeys file size, in bytes

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
        #logger.debug("Verifying token %s with URL %s" % (token, url))
        url = url % ({'token': token})
        # FIXME: log if we nedded to remove evil
        url = re.sub(r'[^A-Za-z0-9:;/.,%!@^&()+ ?=-]', '', url)
        try:
            cmd = "curl -s '%s'" % (url)
            #logger.debug("Running curl: <%s>" % (cmd))
            fo = os.popen(cmd)
            rs = fo.read()
        except IOError, e:
            logger.warning("popen() failed: " + str(e))
            raise self.ErrBadPassword()
        logger.debug("Curl returned <%s>" % (rs))

        if rs == "OK":
            return True
        if rs in ("FAIL", ''):
            raise self.ErrBadPassword()
        raise self.ErrNotice(rs)

    def getConfEntries(self, fn):
        d = open(fn).read(maxConfFileSize)
        if len(d) > maxConfFileSize/2:
            logger.warning("User <%s> has a big (at least %d bytes)"
                           % (user, len(d)))
        for line in d.split('\n'):
            a,b = line.split(None, 1)
            yield a,b

    def run(self):
        user = raw_input("")
        token = raw_input("")
        #logger.debug("Checking token %s for user %s" % (token, user))
        if len(token) < 44:
            return "FAIL"
        keyid = token[-44:][:12]
        fn = os.environ.get(userconf_envname,
                            os.path.join(pwd.getpwnam(user)[5],
                                         ".yubikeys"))
        try:
            for key,url in self.getConfEntries(fn):
                if key == keyid or key == dvorak2qwerty(keyid):
                    logger.debug("Found key <%s>, trying it with url: <%s>"
                                 % (key, url))
                    # FIXME: handle same key, different authserver
                    self.verifyToken(token, url)
                    return "OK"
            raise self.ErrBase("Yubikey not listed as authorized")

        except self.ErrUsername, e:
            logger.debug("User does not have keyid <%s> in their conf"
                         % (keyid))
            return "FAIL"

        except self.ErrNotice, e:
            logger.debug("NOTICE sent to user %s" % (user))
            return str(e)

        except self.ErrBase, e:
            logger.debug("Auth error of user %s: %s" % (user, e))
            return "FAIL"

        except:
            logger.debug("Unknown error for user %s: %s" % (user, str(e)))
            return "FAIL"

def main():
    y = Authenticator()
    res = y.run()
    print res
    #open("/tmp/lalaha","a").write(res+'\n')

if __name__ == '__main__':
    main()
