#!/usr/bin/env python
import os, sys
import re
import winreg
import asn1

KEYNAME_ENCODING = 'windows-1251'

re_keyfile = re.compile(r'\.key$')

def import_binary_regkey(regkey, filename):
    """Import REG_BINARY registry key from file"""
    print("Importing file {}".format(filename))
    subkey = os.path.basename(filename)

    with open(filename, "rb") as f:
        data = f.read()
        winreg.SetValueEx(regkey, subkey, 0, winreg.REG_BINARY, data)

def get_sid():
    """Return current user sid"""
    import win32api, win32security, winerror
    import pywintypes
    from ntsecuritycon import TOKEN_QUERY, TokenUser

    try:
        tok = win32security.OpenThreadToken(win32api.GetCurrentThread(), TOKEN_QUERY, 1)
    except pywintypes.error as e:
        if e.winerror != winerror.ERROR_NO_TOKEN:
            raise
        # attempt to open the process token, since no thread token exists
        tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), TOKEN_QUERY)
    sid, attr = win32security.GetTokenInformation(tok, TokenUser)
    win32api.CloseHandle(tok)

    return win32security.ConvertSidToStringSid(sid)

def get_keyname(dirname):
    """Return key name"""
    filename = os.path.join(dirname, "name.key")
    with open(filename, "rb") as f:
        data = f.read()

    # name.key is a sequence of strings, use the first one
    decoder = asn1.Decoder()
    decoder.start(data)
    tag = decoder.peek()
    assert(tag.nr == asn1.Numbers.Sequence)
    decoder.enter()

    # IA5String is not UTF-8 encoded so decode it manually
    tag = decoder.peek()
    assert(tag.nr == asn1.Numbers.IA5String)
    length = decoder._read_length()
    value = decoder._read_bytes(length)
    keyname = value.decode(KEYNAME_ENCODING)
    return keyname

def main(argv):
    if len(argv) < 2:
        scriptname = os.path.basename(argv[0])
        print("""
Usage: {} dir [sid]
""".format(scriptname), file=sys.stderr)
        return 1
    dir = argv[1]
    print("-- Using key directory {}".format(dir))

    if len(argv) < 3:
        sid = get_sid()
    else:
        sid = argv[1]
    print("-- Using sid {}".format(sid))

    keyname = get_keyname(dir)
    print("-- Using key name {}".format(keyname))

    regkeyname = r'Software\Crypto Pro\Settings\Users\{}\Keys\{}'.format(sid, keyname)
    print("-- Using regkey {}".format(regkeyname))
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, regkeyname) as regkey:
        for root, dirs, files in os.walk(dir):
            for name in files:
                if re_keyfile.search(name):
                    import_binary_regkey(regkey, os.path.join(root, name))

if __name__ == '__main__':
    sys.exit(main(sys.argv))
