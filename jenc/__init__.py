
#import locale
import logging
import os
import sys

# https://github.com/Legrandin/pycryptodome - PyCryptodome (safer/modern PyCrypto)
# http://www.dlitz.net/software/pycrypto/ - PyCrypto - The Python Cryptography Toolkit
import Crypto
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES


class JencException(Exception):
    '''Base jenc exception'''

class UnsupportedMetaData(JencException):
    '''version, meta data, etc. not supported exception'''



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
    if jenc_version not in (b'V001'):
        raise NotImplementedError('jenc version %r', jenc_version)
    jenc_version = jenc_version.decode('us-ascii')
    jenc_version_details = {
        'V001': {
            # note CamelCase to match https://github.com/opensource21/jpencconverter/blob/f65b630ea190e597ff138d9c1ffa9409bb4d56f7/src/main/java/de/stanetz/jpencconverter/cryption/JavaPasswordbasedCryption.java#L229
            'keyFactory': JENC_PBKDF2WithHmacSHA512,
            'keyIterationCount': 10000,  # this is probably too small/few in 2024
            'keyLength': 256,
            'keyAlgorithm': 'AES',
            'keySaltLength': 64,  # in bytes
            'cipher': JENC_AES_GCM_NoPadding,
            'nonceLenth': 32,  # nonceLenth (sic.) == Nonce Length  # in bytes
        },
    }
    this_file_meta = jenc_version_details[jenc_version]
    nonce_bytes = file_object.read(this_file_meta['nonceLenth'])
    salt_bytes = file_object.read(this_file_meta['keySaltLength'])
    content_bytes = file_object.read()  # until EOF
    auth_tag_length = 16  # i.e. 16 * 8 == 128-bits
    auth_tag = content_bytes[-auth_tag_length:]
    content_bytes = content_bytes[:-auth_tag_length]  # FIXME inefficient

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


    # FIXME assuming V001
    # https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
    log.debug('password %r', password)
    if this_file_meta['keyFactory'] == JENC_PBKDF2WithHmacSHA512:
        derived_key = PBKDF2(password, salt_bytes, this_file_meta['keyLength'] // 8, count=this_file_meta['keyIterationCount'], hmac_hash_module=SHA512)
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
    # FIXME block padding needs to be removed
    return plaintext_bytes
