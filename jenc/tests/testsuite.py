#!/usr/bin/env python
# -*- coding: us-ascii -*-
# vim:ts=4:sw=4:softtabstop=4:smarttab:expandtab
"""Test suite for Puren Tonbo

Sample usage:

    python -m jenc.tests.testsuite -v
    python -m jenc.tests.testsuite -v TestJenc

"""

import glob
import os
import pdb
import sys
import shutil
import tempfile
import traceback

from io import BytesIO as FakeFile  # py3

try:
    if sys.version_info < (2, 3):
        raise ImportError
    import unittest2
    unittest = unittest2
except ImportError:
    import unittest
    unittest2 = None

import jenc


is_py3 = sys.version_info >= (3,)
is_win = sys.platform.startswith('win')


class TestUtil(unittest.TestCase):
    def skip(self, reason):
        """Skip current test because of `reason`.

        NOTE currently expects unittest2, and defaults to "pass" if not available.

        unittest2 does NOT work under Python 2.2.
        Could potentially use nose or py.test which has (previously) supported Python 2.2
          * nose http://python-nose.googlecode.com/svn/wiki/NoseWithPython2_2.wiki
          * py.test http://codespeak.net/pipermail/py-dev/2005-February/000203.html
        """
        #self.assertEqual(1, 0)
        if unittest2:
            raise unittest2.SkipTest(reason)
        else:
            raise self.skipTest(reason)  # py3 and 2.7 have this
            """
            print(reason)
            self.fail('SKIP THIS TEST: ' + reason)
            #self.assertTrue(False, reason)
            #raise Exception(reason)
            """

hello_password = 'geheim'
hello_world_plaintext = b"Hello World"
hello_world_v001 = b'V001\xa3\x9d\xf7\xa4\xa7\xa1\xff\x18\x82y\x18\x83\xc6\x97RMgp\xd1\xa6\t\x9c+\xb8\x97\x85U\xed\x02\xca\xaa\xbe[\x92<\xc2\x8cuf\x1b\x03TA&\rkm\x86GH\xd1\xb7\xb5\x1e\x81\xf0\xe4\xa9J\xcei\x130\xe6\xa4\x93\x9aMgh\x9e\xa3\xd3I\xd0a\x98U\x9f6<\x01\xe2A\x88\x9d!\x02\xbe\xf5\xb9\xdd\xb9\xa7\t)N?\x8e\x03K\xb0e?\xd4\x9e\x99\x96\x10R\xf4FC\xe6V\xd7\xdfF\xdbn\xc1bc'

class TestJencUtil(TestUtil):
    def check_get_what_you_put_in(self, original_plaintext, password, version=None, decrypt_password=None):
        decrypt_password = decrypt_password or password
        if version:
            encrypted_bytes = jenc.encrypt(password, original_plaintext, jenc_version=version)
            self.assertEqual(version.encode('us-ascii'), encrypted_bytes[:4])
        else:
            encrypted_bytes = jenc.encrypt(password, original_plaintext)
        plaintext_bytes = jenc.decrypt(decrypt_password, encrypted_bytes)

        self.assertEqual(plaintext_bytes, original_plaintext)

    def check_same_input_different_crypted_text(self, original_plaintext, password, version=None):
        if version:
            encrypted_bytes1 = jenc.encrypt(password, original_plaintext, jenc_version=version)
            self.assertEqual(version.encode('us-ascii'), encrypted_bytes1[:4])
        else:
            encrypted_bytes1 = jenc.encrypt(password, original_plaintext)
        plaintext_bytes1 = jenc.decrypt(password, encrypted_bytes1)

        if version:
            encrypted_bytes2 = jenc.encrypt(password, original_plaintext, jenc_version=version)
            self.assertEqual(version.encode('us-ascii'), encrypted_bytes2[:4])
        else:
            encrypted_bytes2 = jenc.encrypt(password, original_plaintext)
        plaintext_bytes2 = jenc.decrypt(password, encrypted_bytes2)

        self.assertEqual(original_plaintext, plaintext_bytes1)
        self.assertEqual(original_plaintext, plaintext_bytes2)
        self.assertNotEqual(encrypted_bytes1, encrypted_bytes2)

class TestJencErrors(TestJencUtil):
    def test_hello_world_decrypt_wrong_password(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        decrypt_password = 'bad password'  # deliberately different
        original_plaintext = b"Hello World"
        self.assertNotEqual(password, decrypt_password)
        self.assertRaises(jenc.JencDecryptError, self.check_get_what_you_put_in, original_plaintext, password, decrypt_password=decrypt_password)

    def test_hello_world_decrypt_bad_version(self):
        encrypted_bytes = jenc.decrypt(hello_password, hello_world_v001)
        self.assertEqual(encrypted_bytes, hello_world_plaintext)
        invalid_version = b'AAAA'
        self.assertRaises(jenc.UnsupportedMetaData, jenc.decrypt, hello_password, invalid_version + hello_world_v001[4:])
# TODO test decryption failure on corrupted file (change a byte, hmac and also payload).


class TestJenc(TestJencUtil):

    def test_hello_world_enc_dec_default_encryption(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        self.check_get_what_you_put_in(original_plaintext, password)

    def test_hello_world_encs_different_each_time_encryption(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        self.check_same_input_different_crypted_text(original_plaintext, password)

    def test_hello_world_enc_dec_default_v001(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        self.check_get_what_you_put_in(original_plaintext, password, version='V001')

    def test_hello_world_encs_different_each_time_v001(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        self.check_same_input_different_crypted_text(original_plaintext, password, version='V001')

    def test_hello_world_enc_dec_default_u001(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        self.check_get_what_you_put_in(original_plaintext, password, version='U001')

    def test_hello_world_encs_different_each_time_u001(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        self.check_same_input_different_crypted_text(original_plaintext, password, version='U001')


class TestJencWhiteBox(TestJencUtil):
    """Look inside jenc for all versions and test them, hopefully catch any new versions that are not explictly (manually) added above
    Actual number of tests is = test method count * real number of versions
    """

    def test_hello_world_enc_dec_default_all_versions(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        for version in jenc.jenc_version_details:
            self.check_get_what_you_put_in(original_plaintext, password, version=version)

    def test_hello_world_encs_different_each_time_all_versions(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        for version in jenc.jenc_version_details:
            self.check_same_input_different_crypted_text(original_plaintext, password, version=version)


class TestJencFiles(TestJencUtil):
    data_folder = os.path.join(
                    os.path.dirname(jenc.tests.__file__),
                    'data'
    )
    password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted

    def check_decrypt_file(self, encrypted_filename, plaintext_filename):
        encrypted_file = open(os.path.join(self.data_folder, encrypted_filename), 'rb')
        plaintext_file = open(os.path.join(self.data_folder, plaintext_filename), 'rb')

        encrypted = encrypted_file.read()
        plaintext = plaintext_file.read()

        encrypted_file.close()
        plaintext_file.close()

        test_plaintext_bytes = jenc.decrypt(self.password, encrypted)
        #print('%d : %r' % (len(test_plaintext_bytes), test_plaintext_bytes))
        #print('%d : %r' % (len(plaintext), plaintext))
        #print('%d' % len(test_plaintext_bytes))
        #print('%d' % len(plaintext))

        test_plaintext_bytes = test_plaintext_bytes.replace(b'\r', b'')
        plaintext = plaintext.replace(b'\r', b'')
        #print('%d' % len(test_plaintext_bytes))
        #print('%d' % len(plaintext))

        self.assertEqual(plaintext, test_plaintext_bytes)


    def test_jpencconverter_test3(self):
        self.check_decrypt_file('Test3.md.jenc', 'Test3.md')  # NOTE jpencconverter trims off newline at EOF!

    def test_jpencconverter_u001(self):
        self.check_decrypt_file('test.u001_winnewlines.md.jenc', 'test.u001.md')  # NOTE jpencconverter trims off newline at EOF!

    def test_jpencconverter_v001(self):
        self.check_decrypt_file('test.v001_winnewlines.md.jenc', 'test.v001.md')  # NOTE jpencconverter trims off newline at EOF!


def main():
    print(sys.version.replace('\n', ' '))

    if os.environ.get('DEBUG_ON_FAIL'):
        unittest.main(testRunner=debugTestRunner())
        ##unittest.main(testRunner=debugTestRunner(pywin.debugger.post_mortem))
        ##unittest.findTestCases(__main__).debug()
    else:
        unittest.main()

if __name__ == '__main__':
    main()
