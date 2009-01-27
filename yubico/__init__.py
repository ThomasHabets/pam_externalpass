VERSION = (0, 1)

def get_version():
    '''Returns the version as a human-formatted string.

    The string follows the format of X.y.z, where:

    X is the version number,
    y is the patch release, and
    z is the revision number.'''

    return "%s.%s.%s" % VERSION
