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

class TestJenc(TestUtil):
    def check_get_what_you_put_in(self, original_plaintext, password):
        encrypted_bytes = jenc.encrypt(password, original_plaintext)
        plaintext_bytes = jenc.decrypt(password, encrypted_bytes)

        self.assertEqual(plaintext_bytes, original_plaintext)

    def check_same_input_different_crypted_text(self, original_plaintext, password):
        encrypted_bytes1 = jenc.encrypt(password, original_plaintext)
        plaintext_bytes1 = jenc.decrypt(password, encrypted_bytes1)

        encrypted_bytes2 = jenc.encrypt(password, original_plaintext)
        plaintext_bytes2 = jenc.decrypt(password, encrypted_bytes2)

        self.assertEqual(original_plaintext, plaintext_bytes1)
        self.assertEqual(original_plaintext, plaintext_bytes2)
        self.assertNotEqual(encrypted_bytes1, encrypted_bytes2)

    def test_hello_world_enc_dec(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        self.check_get_what_you_put_in(original_plaintext, password)

    def test_hello_world_encs_different_each_time(self):
        password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
        original_plaintext = b"Hello World"
        self.check_same_input_different_crypted_text(original_plaintext, password)


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
