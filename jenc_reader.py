
import locale
import logging
import os
import sys

# https://github.com/Legrandin/pycryptodome - PyCryptodome (safer/modern PyCrypto)
# http://www.dlitz.net/software/pycrypto/ - PyCrypto - The Python Cryptography Toolkit
import Crypto
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES


# create log
log = logging.getLogger("mylogger")
log.setLevel(logging.DEBUG)
disable_logging = False
#disable_logging = True
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
log.debug('encodings %r', (sys.getdefaultencoding(), sys.getfilesystemencoding(), locale.getdefaultlocale()))


filename = os.environ['JENC_FILENAME']
password = os.environ['PASSWORD']
file_object = open(filename, 'rb')

"""
     * 4 bytes - define the version.
     * salt bytes - bytes to salt the password. The length depends on version.
     * nonce bytes - bytes as nonce for cipher depends. The length  on version.
     * content bytes - the encrypted content-bytes.

V001("PBKDF2WithHmacSHA512", 10000, 256, "AES", 64, "AES/GCM/NoPadding", 32),
/**
 * Weaker version of V001. Needed for old android-devices.
 * @deprecated please use {@link #V001} if possible.
 */
U001("PBKDF2WithHmacSHA1", 10000, 256, "AES", 64, "AES/GCM/NoPadding", 32);
Version(String keyFactory, int keyIterationCount, int keyLength, String keyAlgorithm, int keySaltLength, String cipher, int nonceLenth)
"""
jenc_version = file_object.read(4)

log.debug('jenc_version %r', jenc_version)
if jenc_version not in (b'V001'):
    raise NotImplementedError('jenc version %r', jenc_version)
jenc_version = jenc_version.decode('us-ascii')
jenc_version_details = {
    'V001': {
        # note CamelCase to match https://github.com/opensource21/jpencconverter/blob/f65b630ea190e597ff138d9c1ffa9409bb4d56f7/src/main/java/de/stanetz/jpencconverter/cryption/JavaPasswordbasedCryption.java#L229
        'keyFactory': 'PBKDF2WithHmacSHA512',
        'keyIterationCount': 10000,  # this is probably too small/few in 2024
        'keyLength': 256,
        'keyAlgorithm': 'AES',
        'keySaltLength': 64,
        'cipher': 'AES/GCM/NoPadding',
        'nonceLenth': 32,  # nonceLenth (sic.) == Nonce Length
    },
}
this_file_meta = jenc_version_details[jenc_version]
salt_bytes = file_object.read(this_file_meta['keySaltLength'])  # TODO review bit count versus byte count
nonce_bytes = file_object.read(this_file_meta['nonceLenth'])  # TODO review bit count versus byte count
content_bytes = file_object.read()  # until EOF




# FIXME assuming V001
# https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
log.debug('password %r', password)
derived_key = PBKDF2(password, salt_bytes, this_file_meta['keyLength'] // 8, count=this_file_meta['keyIterationCount'], hmac_hash_module=SHA512)
log.debug('derived_key %r', derived_key)
log.debug('derived_key len %r', len(derived_key))

cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce_bytes)
log.debug('cipher %r', cipher)
log.debug('content_bytes %r', content_bytes)
plaintext = cipher.decrypt(content_bytes)
log.debug('plaintext %r', plaintext)

file_object.close()
