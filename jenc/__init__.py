#!/usr/bin/env python
# -*- coding: us-ascii -*-
# vim:ts=4:sw=4:softtabstop=4:smarttab:expandtab
"""Pure Python jenc / Markor / jpencconverter compatible encrypt/decrypt package

  * Markor
      * https://github.com/gsantner/markor/blob/master/app/thirdparty/java/other/de/stanetz/jpencconverter/JavaPasswordbasedCryption.java
  * jpencconverter
      * https://gitlab.com/opensource21/jpencconverter
      * https://github.com/opensource21/jpencconverter

"""

import getpass
#import locale
import logging
import optparse
import os
import sys
import time

# https://github.com/Legrandin/pycryptodome - PyCryptodome (safer/modern PyCrypto)
# http://www.dlitz.net/software/pycrypto/ - PyCrypto - The Python Cryptography Toolkit
import Crypto
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from Crypto.Hash import SHA512
from Crypto.Cipher import AES

from Cryptodome.Random import get_random_bytes  # FIXME

from ._version import __version__, __version_info__


is_py3 = sys.version_info >= (3,)


class JencException(Exception):
    '''Base jenc exception'''

class UnsupportedMetaData(JencException):
    '''version, meta data, etc. not supported exception'''

class JencDecryptError(JencException):
    '''Unable to decrypt, likely wrong password but could be corrupted encrypted input'''



# create log
log = logging.getLogger("jenc")
log.setLevel(logging.DEBUG)
disable_logging = True
#disable_logging = False  # DEBUG
if disable_logging:
    log.setLevel(logging.NOTSET)  # only logs; WARNING, ERROR, CRITICAL

ch = logging.StreamHandler()  # use stdio

if sys.version_info >= (2, 5):
    # 2.5 added function name tracing
    logging_fmt_str = "%(process)d %(thread)d %(asctime)s - %(name)s %(filename)s:%(lineno)d %(funcName)s() - %(levelname)s - %(message)s"
else:
    if JYTHON_RUNTIME_DETECTED:
        # process is None under Jython 2.2
        logging_fmt_str = "%(thread)d %(asctime)s - %(name)s %(filename)s:%(lineno)d - %(levelname)s - %(message)s"
    else:
        logging_fmt_str = "%(process)d %(thread)d %(asctime)s - %(name)s %(filename)s:%(lineno)d - %(levelname)s - %(message)s"

formatter = logging.Formatter(logging_fmt_str)
ch.setFormatter(formatter)
log.addHandler(ch)

# FIXME - DeprecationWarning: 'locale.getdefaultlocale' is deprecated and slated for removal in Python 3.15. Use setlocale(), getencoding() and getlocale() instead.
#log.debug('encodings %r', (sys.getdefaultencoding(), sys.getfilesystemencoding(), locale.getdefaultlocale()))


JENC_PBKDF2WithHmacSHA1 = 'PBKDF2WithHmacSHA1'
JENC_PBKDF2WithHmacSHA512 = 'PBKDF2WithHmacSHA512'
JENC_AES_GCM_NoPadding = 'AES/GCM/NoPadding'

"""
     * 4 bytes - define the version.
     * nonce bytes - bytes as nonce for cipher depends. The length  on version.
     * salt bytes - bytes to salt the password. The length depends on version.
     * content bytes - the encrypted content-bytes.

V001("PBKDF2WithHmacSHA512", 10000, 256, "AES", 64, "AES/GCM/NoPadding", 32),
/**
 * Weaker version of V001. Needed for old android-devices.
 * @deprecated please use {@link #V001} if possible.
 */
U001("PBKDF2WithHmacSHA1", 10000, 256, "AES", 64, "AES/GCM/NoPadding", 32);
Version(String keyFactory, int keyIterationCount, int keyLength, String keyAlgorithm, int keySaltLength, String cipher, int nonceLenth)
"""

jenc_version_details = {
    # Markor / jpencconverter JavaPasswordbasedCryption.java enum Version
    # note CamelCase (and typo/contraction) to match Java implementation
    #   * https://github.com/gsantner/markor/blob/9ff073aa1f1fbabc9153636a7a0af674786ffb53/app/thirdparty/java/other/de/stanetz/jpencconverter/JavaPasswordbasedCryption.java#L253
    #   * https://github.com/opensource21/jpencconverter/blob/f65b630ea190e597ff138d9c1ffa9409bb4d56f7/src/main/java/de/stanetz/jpencconverter/cryption/JavaPasswordbasedCryption.java#L229
    # U001("PBKDF2WithHmacSHA1", 10000, 256, "AES", 64, "AES/GCM/NoPadding", 32);
    # V001("PBKDF2WithHmacSHA512", 10000, 256, "AES", 64, "AES/GCM/NoPadding", 32),
    'U001': {  # NOTE Deprecated, i.e. not recommended
        'keyFactory': JENC_PBKDF2WithHmacSHA1,
        'keyIterationCount': 10000,  # this is probably too small/few in 2024
        'keyLength': 256,
        'keyAlgorithm': 'AES',
        'keySaltLength': 64,  # in bytes
        'cipher': JENC_AES_GCM_NoPadding,
        'nonceLenth': 32,  # nonceLenth (sic.) == Nonce Length, i.e. IV length  # in bytes
    },
    'V001': {
        'keyFactory': JENC_PBKDF2WithHmacSHA512,
        'keyIterationCount': 10000,  # this is probably too small/few in 2024
        'keyLength': 256,
        'keyAlgorithm': 'AES',
        'keySaltLength': 64,  # in bytes
        'cipher': JENC_AES_GCM_NoPadding,
        'nonceLenth': 32,  # nonceLenth (sic.) == Nonce Length, i.e. IV length  # in bytes
    },
}
AUTH_TAG_LENGTH = 16  # i.e. 16 * 8 == 128-bits ; Markor / jpencconverter JavaPasswordbasedCryption.java : getCipher(); GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);


def jenc_version_check(jenc_version):
    if isinstance(jenc_version, bytes):
        jenc_version = jenc_version.decode('us-ascii')
    if jenc_version not in jenc_version_details:
        raise UnsupportedMetaData('jenc version %r', jenc_version)

def decrypt(password, encrypt_bytes):
    """Takes in:
        password string (not bytes)
        encrypt_bytes
    Returns plaintext_bytes.

    Sample code:

        import jenc

        password = 'geheim'
        encrypted_bytes = jenc.encrypt(password, b"Hello World")
        plaintext_bytes = jenc.decrypt(password, encrypted_bytes)
    """
    start_offset, end_offset = 0, 4  # Markor / jpencconverter JavaPasswordbasedCryption.java enum Version NAME_LENGTH
    jenc_version = encrypt_bytes[:end_offset]
    log.debug('jenc_version %r', jenc_version)
    jenc_version_check(jenc_version)
    jenc_version = jenc_version.decode('us-ascii')
    this_file_meta = jenc_version_details[jenc_version]

    start_offset, end_offset = end_offset, end_offset + this_file_meta['nonceLenth']
    nonce_bytes = encrypt_bytes[start_offset:end_offset]

    log.debug('%d nonce_bytes %r', len(nonce_bytes), nonce_bytes)
    log.debug('%d nonce_bytes hex %r', len(nonce_bytes), nonce_bytes.hex())

    start_offset, end_offset = end_offset, end_offset + this_file_meta['keySaltLength']
    salt_bytes = encrypt_bytes[start_offset:end_offset]

    log.debug('%d salt_bytes %r', len(salt_bytes), salt_bytes)
    log.debug('%d salt_bytes hex %r', len(salt_bytes), salt_bytes.hex())

    start_offset, end_offset = end_offset, -AUTH_TAG_LENGTH
    content_bytes = encrypt_bytes[start_offset:end_offset]
    log.debug('%d content_bytes %r', len(content_bytes), content_bytes)
    log.debug('%d content_bytes hex %r', len(content_bytes), content_bytes.hex())

    auth_tag = encrypt_bytes[-AUTH_TAG_LENGTH:]
    log.debug('%d auth_tag %r', len(auth_tag), auth_tag)
    log.debug('%d auth_tag hex %r', len(auth_tag), auth_tag.hex())

    # https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
    log.debug('password %r', password)
    if this_file_meta['keyFactory'] == JENC_PBKDF2WithHmacSHA512:
        derived_key = PBKDF2(password, salt_bytes, this_file_meta['keyLength'] // 8, count=this_file_meta['keyIterationCount'], hmac_hash_module=SHA512)
    elif this_file_meta['keyFactory'] == JENC_PBKDF2WithHmacSHA1:
        derived_key = PBKDF2(password, salt_bytes, this_file_meta['keyLength'] // 8, count=this_file_meta['keyIterationCount'], hmac_hash_module=SHA1)
    else:
        raise UnsupportedMetaData('keyFactory %r' % this_file_meta['keyFactory'])
    log.debug('derived_key %r', derived_key)
    log.debug('derived_key len %r', len(derived_key))

    if this_file_meta['cipher'] == JENC_AES_GCM_NoPadding:
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce_bytes)
    else:
        raise UnsupportedMetaData('cipher %r' % this_file_meta['cipher'])

    log.debug('cipher %r', cipher)
    log.debug('content_bytes %r', content_bytes)
    #plaintext_bytes = cipher.decrypt(content_bytes)  # if you want to decrypt BUT skip MAC check
    try:
        plaintext_bytes = cipher.decrypt_and_verify(content_bytes, auth_tag)  # TODO catch ValueError: MAC check failed
    except ValueError as info:
        raise JencDecryptError(info)
    log.debug('plaintext_bytes %r', plaintext_bytes)
    original_length = len(content_bytes)
    return plaintext_bytes


def encrypt(password, plaintext_bytes, jenc_version='V001'):
    """Takes in:
        file-like object
        password string (not bytes)
        plaintext_bytes
        version (string)
    Returns encrypted bytes.

    Sample code:

        import jenc

        password = 'geheim'
        encrypted_bytes = jenc.encrypt(password, b"Hello World")
    """
    jenc_version_check(jenc_version)
    this_file_meta = jenc_version_details[jenc_version]
    nonce_bytes = get_random_bytes(this_file_meta['nonceLenth'])
    salt_bytes = get_random_bytes(this_file_meta['keySaltLength'])

    log.debug('password %r', password)
    if this_file_meta['keyFactory'] == JENC_PBKDF2WithHmacSHA512:
        derived_key = PBKDF2(password, salt_bytes, this_file_meta['keyLength'] // 8, count=this_file_meta['keyIterationCount'], hmac_hash_module=SHA512)
    elif this_file_meta['keyFactory'] == JENC_PBKDF2WithHmacSHA1:
        derived_key = PBKDF2(password, salt_bytes, this_file_meta['keyLength'] // 8, count=this_file_meta['keyIterationCount'], hmac_hash_module=SHA1)
    else:
        raise UnsupportedMetaData('keyFactory %r' % this_file_meta['keyFactory'])
    log.debug('derived_key %r', derived_key)
    log.debug('derived_key len %r', len(derived_key))

    if this_file_meta['cipher'] == JENC_AES_GCM_NoPadding:
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce_bytes)
    else:
        raise UnsupportedMetaData('cipher %r' % this_file_meta['cipher'])

    log.debug('cipher %r', cipher)

    crypted_bytes, auth_tag = cipher.encrypt_and_digest(plaintext_bytes)

    return jenc_version.encode('us-ascii') + nonce_bytes + salt_bytes + crypted_bytes + auth_tag


def encrypt_file_handle(file_object, password, plaintext_bytes, jenc_version='V001'):
    """Takes in:
        file-like object
        password string (not bytes)
        plaintext_bytes
        version (string)
    Sample code:

        import jenc

        filename = 'testout.md.jenc'
        password = 'geheim'
        file_object = open(filename, 'wb')
        jenc.encrypt_file_handle(file_object, password, b"Hello World")
        file_object.close()
    """
    encrypt_bytes = encrypt(password, plaintext_bytes, jenc_version=jenc_version)
    file_object.write(encrypt_bytes)


def decrypt_file_handle(file_object, password):
    """Takes in:
        file-like object
        password string (not bytes)
    And return plain text bytes. Java version of jenc uses utf-8 for string.

    Sample code:

        import jenc

        filename = 'Test3.md.jenc'  # from demo test data for jenc java
        password = 'geheim'

        file_object = open(filename, 'rb')
        plaintext_bytes = jenc.decrypt_file_handle(file_object, password)
        file_object.close()

        print('%r' % plaintext_bytes)
        plaintext = plaintext_bytes.decode('utf-8', errors='replace')
        print('%r' % plaintext)
        print('%s' % plaintext)
    """
    jenc_version = file_object.read(4)

    log.debug('jenc_version %r', jenc_version)
    jenc_version_check(jenc_version)
    jenc_version = jenc_version.decode('us-ascii')
    this_file_meta = jenc_version_details[jenc_version]
    nonce_bytes = file_object.read(this_file_meta['nonceLenth'])
    salt_bytes = file_object.read(this_file_meta['keySaltLength'])
    content_bytes = file_object.read()  # until EOF
    auth_tag = content_bytes[-AUTH_TAG_LENGTH:]
    content_bytes = content_bytes[:-AUTH_TAG_LENGTH]  # FIXME inefficient, consider reading entire file and calling decrypt() instead

    log.debug('%d nonce_bytes %r', len(nonce_bytes), nonce_bytes)
    log.debug('%d nonce_bytes hex %r', len(nonce_bytes), nonce_bytes.hex())

    log.debug('%d salt_bytes %r', len(salt_bytes), salt_bytes)
    log.debug('%d salt_bytes hex %r', len(salt_bytes), salt_bytes.hex())

    log.debug('%d auth_tag %r', len(auth_tag), auth_tag)
    log.debug('%d auth_tag hex %r', len(auth_tag), auth_tag.hex())

    #  64 salt_bytes hex '05fa11953346421ea3698beca3f2142e53f538743cc522ea5f3a68f41e2a1a8e6c373d55f41fcf9915846707c72d2610fcfe8690cbe28dbfa1716023f851f6dd'
    """
    java debug

    salt 128 chracters in hex, so 64 bytes
    nonce 64 chracters in hex, so 32 bytes

    -----------------------------------

    contents should be from Test3.md.jenc
    clach04DEBUG decryptStaticByte() jenc hex:
                    56303031
    nonce           05FA11953346421EA3698BECA3F2142E53F538743CC522EA5F3A68F41E2A1A8E
    salt            6C373D55F41FCF9915846707C72D2610FCFE8690CBE28DBFA1716023F851F6DD62CF7D4313130FB04F69F18BD9AD5894B15A1E1F496FC908CE0BE4263D94A04D
    encoded bytes   9EF1DB50D146F805380156A03B24E42DFDD331F843BF1ED25182A80A39E2C53053402A0F2CDC29D918479DA99276D0ACD4DA6311C050E9603EAE14788D572DE6BEB0994771D9C45E5816C43D4D8BC688D09D5426F1E82960303E1E91072B6667BBB4A3516D3386A5DCC4D4DD29B8747D43BD6659F3BD729B7E9DE112CAFA4A6C6627C96279B8706D48EAEC5B3D58ABFB635ACC4878

    clach04DEBUG decryptStaticByte() jenc hex: 5630303105FA11953346421EA3698BECA3F2142E53F538743CC522EA5F3A68F41E2A1A8E6C373D55F41FCF9915846707C72D2610FCFE8690CBE28DBFA1716023F851F6DD62CF7D4313130FB04F69F18BD9AD5894B15A1E1F496FC908CE0BE4263D94A04D9EF1DB50D146F805380156A03B24E42DFDD331F843BF1ED25182A80A39E2C53053402A0F2CDC29D918479DA99276D0ACD4DA6311C050E9603EAE14788D572DE6BEB0994771D9C45E5816C43D4D8BC688D09D5426F1E82960303E1E91072B6667BBB4A3516D3386A5DCC4D4DD29B8747D43BD6659F3BD729B7E9DE112CAFA4A6C6627C96279B8706D48EAEC5B3D58ABFB635ACC4878
    clach04DEBUG decryptBytes() salt hex: 6C373D55F41FCF9915846707C72D2610FCFE8690CBE28DBFA1716023F851F6DD62CF7D4313130FB04F69F18BD9AD5894B15A1E1F496FC908CE0BE4263D94A04D
    clach04DEBUG decryptBytes() nonce hex: 05FA11953346421EA3698BECA3F2142E53F538743CC522EA5F3A68F41E2A1A8E
    clach04DEBUG decryptBytes() encodedBytes hex: 9EF1DB50D146F805380156A03B24E42DFDD331F843BF1ED25182A80A39E2C53053402A0F2CDC29D918479DA99276D0ACD4DA6311C050E9603EAE14788D572DE6BEB0994771D9C45E5816C43D4D8BC688D09D5426F1E82960303E1E91072B6667BBB4A3516D3386A5DCC4D4DD29B8747D43BD6659F3BD729B7E9DE112CAFA4A6C6627C96279B8706D48EAEC5B3D58ABFB635ACC4878
    clach04DEBUG decryptBytes() END --------

    -----------------------------------

    """


    # https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
    log.debug('password %r', password)
    if this_file_meta['keyFactory'] == JENC_PBKDF2WithHmacSHA512:
        derived_key = PBKDF2(password, salt_bytes, this_file_meta['keyLength'] // 8, count=this_file_meta['keyIterationCount'], hmac_hash_module=SHA512)
    elif this_file_meta['keyFactory'] == JENC_PBKDF2WithHmacSHA1:
        derived_key = PBKDF2(password, salt_bytes, this_file_meta['keyLength'] // 8, count=this_file_meta['keyIterationCount'], hmac_hash_module=SHA1)
    else:
        raise UnsupportedMetaData('keyFactory %r' % this_file_meta['keyFactory'])
    log.debug('derived_key %r', derived_key)
    log.debug('derived_key len %r', len(derived_key))

    if this_file_meta['cipher'] == JENC_AES_GCM_NoPadding:
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce_bytes)
    else:
        raise UnsupportedMetaData('cipher %r' % this_file_meta['cipher'])

    log.debug('cipher %r', cipher)
    log.debug('content_bytes %r', content_bytes)
    #plaintext_bytes = cipher.decrypt(content_bytes)  # if you want to decrypt BUT skip MAC check
    plaintext_bytes = cipher.decrypt_and_verify(content_bytes, auth_tag)  # TODO catch ValueError: MAC check failed
    log.debug('plaintext_bytes %r', plaintext_bytes)
    original_length = len(content_bytes)
    return plaintext_bytes


def main(argv=None):
    if argv is None:
        argv = sys.argv

    # python -m jenc
    usage = "usage: %prog [options] in_filename"
    parser = optparse.OptionParser(
        usage=usage,
        version="%prog " + __version__,
        description="Command line tool to encrypt/decrypt; .jenc / Markor / jpencconverter files"
    )
    parser.add_option("-o", "--output", dest="out_filename", default='-', help="write output to FILE", metavar="FILE")
    parser.add_option("-d", "--decrypt", action="store_true", dest="decrypt", default=True, help="decrypt in_filename")
    parser.add_option("-e", "--encrypt", action="store_false", dest="decrypt", help="encrypt in_filename")
    #parser.add_option("-c", "--codec", help="File encoding", default='utf-8')  # probably not needed, treat in/out as raw bytes
    parser.add_option("-E", "--envvar", help="Name of environment variable to get password from (defaults to JENC_PASSWORD) - unsafe", default="JENC_PASSWORD")  # similar to https://ccrypt.sourceforge.net/
    parser.add_option("-p", "--password", help="password, if omitted but OS env JENC_PASSWORD is set use that, if missing prompt - unsafe")
    parser.add_option("-P", "--password_file", help="file name where password is to be read from, trailing blanks are ignored")
    parser.add_option("-j", "--jenc-version", "--jenc_version", help="jenc version to use, case sensitive")
    parser.add_option("-v", "--verbose", action="store_true")
    parser.add_option("-s", "--silent", help="if specified do not warn about stdin using", action="store_false", default=True)

    (options, args) = parser.parse_args(argv[1:])
    #print('%r' % ((options, args),))
    verbose = options.verbose
    if verbose:
        print(sys.version.replace('\n', ' '))

    try:
        in_filename = args[0]
    except IndexError:
        # no filename specified so default to stdin
        in_filename = '-'

    if options.password_file:
        f = open(options.password_file, 'rb')
        password_file = f.read()
        f.close()
        password_file = password_file.strip()
    else:
        password_file = None
    password = options.password or password_file or os.environ.get(options.envvar or 'JENC_PASSWORD') or getpass.getpass("Password:")
    decrypt_mode = options.decrypt  # TODO possible additional heuristics; filename extension, read the first bytes and sniff/magic value match it
    out_filename = options.out_filename

    if in_filename == '-':
        if is_py3:
            in_file = sys.stdin.buffer
        else:
            in_file = sys.stdin
        if options.silent:
            sys.stderr.write('Read in from stdin...')
            sys.stderr.flush()
        # TODO for py3 handle string versus bytes
    else:
        in_file = open(in_filename, 'rb')
    if out_filename == '-':
        if is_py3:
            out_file = sys.stdout.buffer
        else:
            out_file = sys.stdout
        # handle string versus bytes....?
    else:
        out_file = open(out_filename, 'wb')

    in_file_bytes = in_file.read()  # read all in at once
    start_time = time.time()
    failed = True
    try:
        if decrypt_mode:
            #import pdb ; pdb.set_trace()
            test_plaintext_bytes = decrypt(password, in_file_bytes)
            out_file.write(test_plaintext_bytes)
            failed = False
        else:
            # encrypt
            if options.jenc_version:
                encrypted_bytes = encrypt(password, in_file_bytes, jenc_version=options.jenc_version)
            else:
                encrypted_bytes = encrypt(password, in_file_bytes)
            out_file.write(encrypted_bytes)
            failed = False
    except JencException as info:  # TODO catch additional specific jenc exceptions
        print("JencException %r" % (info,))
    except Exception as info:  # TODO catch specific jenc exceptions
        print("Exception %r" % (info,))
    finally:
        if in_file != sys.stdin:
            in_file.close()
        if out_file != sys.stdout:
            out_file.close()
    stop_time = time.time()
    sys.stderr.write('\ntook %f secs' % (stop_time - start_time,))
    sys.stderr.flush()

    if failed:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
