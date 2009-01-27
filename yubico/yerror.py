import urllib
import socket
import re, os, sys, string

class responseError( Exception ):
    def __init__( self, value ):
        self.value = value

    def __str__( self ):
        return repr( self.value )

if __name__ == '__main__':
    try:
        raise responseError("OK")
    except responseError, e:
        print "An error has occurred: ", e.value
