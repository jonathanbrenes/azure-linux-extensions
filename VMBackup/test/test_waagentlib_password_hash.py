#!/usr/bin/env python

import os
import sys
import unittest
import unittest.mock as mock


TEST_DIR = os.path.dirname(os.path.abspath(__file__))
VMBACKUP_DIR = os.path.dirname(TEST_DIR)
REPO_ROOT = os.path.dirname(VMBACKUP_DIR)

for path in [REPO_ROOT, VMBACKUP_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

import main.WaagentLib as waagent_lib


class TestWaagentLibPasswordHash(unittest.TestCase):

    def test_hash_verifies_with_crypt(self):
        if not waagent_lib.cryptImported:
            self.skipTest("Neither 'crypt' nor 'legacycrypt' is available")

        distro = waagent_lib.AbstractDistro()
        password = "TestP@ssw0rd!"
        hash_val = distro.gen_password_hash(password, crypt_id=6, salt_len=10)

        self.assertTrue(hash_val.startswith("$6$"))
        self.assertEqual(waagent_lib.crypt(password, hash_val), hash_val)

    def test_passlib_fallback_hash_verifies(self):
        if not waagent_lib.passLibImported:
            self.skipTest("'passlib' is not available")

        with mock.patch.object(waagent_lib, 'cryptImported', False), \
             mock.patch.object(waagent_lib, 'passLibImported', True):
            distro = waagent_lib.AbstractDistro()
            password = "TestP@ssw0rd!"
            hash_val = distro.gen_password_hash(password, crypt_id=6, salt_len=10)

        self.assertTrue(hash_val.startswith("$6$"))
        self.assertTrue(waagent_lib.sha512_crypt.verify(password, hash_val))

    def test_gen_password_hash_raises_when_no_library_available(self):
        with mock.patch.object(waagent_lib, 'cryptImported', False), \
             mock.patch.object(waagent_lib, 'passLibImported', False):
            distro = waagent_lib.AbstractDistro()
            with self.assertRaises(ImportError):
                distro.gen_password_hash("SomePassword1!", crypt_id=6, salt_len=10)


if __name__ == '__main__':
    unittest.main()