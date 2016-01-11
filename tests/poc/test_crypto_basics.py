import unittest

import cryptography.hazmat.backends.openssl.backend as openssl
import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes

class HashTestCases(unittest.TestCase):
    def test_hash_sha1(self):
        digest = hashes.Hash(hashes.SHA1(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(digest.finalize().hex(), 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3')

    def test_hash_sha256(self):
        digest = hashes.Hash(hashes.SHA256(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(digest.finalize().hex(), '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')

    def test_hash_sha384(self):
        digest = hashes.Hash(hashes.SHA384(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(digest.finalize().hex(), '768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9')

    def test_hash_sha512(self):
        digest = hashes.Hash(hashes.SHA512(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(digest.finalize().hex(), 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff')

class RSATestCases(unittest.TestCase):
    def setUp(self):
        '''
        Test loading PKCS8 file, generated externally by OpenSSL
        '''
        with open('tests/poc/test-rsa.pem', mode='rb') as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = None,
                backend = openssl
            )
            self._public_key = self._private_key.public_key()

    def test_rsa_sign(self):
        '''
        Test signing of message, using RSA and PKCS1v15 padding, which provides a consistent result.
        '''
        message = b'test'
        signature = bytes.fromhex('63cd456e8455f87648db284479b452c3580582fc500e381467c6950b3a1ad4db4ceb3c6bb014c5188f349864e94ad4d86c562ef574ea2a3db997a82b40b141028e35e0060c38ac7a4adb4d1b0aab7145cb3edade0a5761546ad52aabed899ac21419afb6a80b0b631a4467ff905724a2f616fe49322e6a12109e9eb1318d57cdfd109000a674dfaad5f1932d4ea112e46bf35070b3c693120a9241cd726990fc2ee994bd61a91df78f93f24e14ed346546886053994b559dfbedc9b37667247403475e9a60855140bb2eeab930cc6e57ae0f068ff8dc89edf1f0095b39eae4fd07b8bfd90a75e48930a519de31b7eee1d41c6c73dee9b02cbc3badcc3f32cac8')

        signer = self._private_key.signer(
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signer.update(message)
        self.assertEqual(signer.finalize(), signature)

    def test_rsa_verify(self):
        '''
        Verify signature, using RSA, and PKCS1v15 padding, which provides a consistent result.
        '''
        message = b'test'
        signature = bytes.fromhex('63cd456e8455f87648db284479b452c3580582fc500e381467c6950b3a1ad4db4ceb3c6bb014c5188f349864e94ad4d86c562ef574ea2a3db997a82b40b141028e35e0060c38ac7a4adb4d1b0aab7145cb3edade0a5761546ad52aabed899ac21419afb6a80b0b631a4467ff905724a2f616fe49322e6a12109e9eb1318d57cdfd109000a674dfaad5f1932d4ea112e46bf35070b3c693120a9241cd726990fc2ee994bd61a91df78f93f24e14ed346546886053994b559dfbedc9b37667247403475e9a60855140bb2eeab930cc6e57ae0f068ff8dc89edf1f0095b39eae4fd07b8bfd90a75e48930a519de31b7eee1d41c6c73dee9b02cbc3badcc3f32cac8')

        verifier = self._public_key.verifier(
            signature,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        verifier.update(message)
        verifier.verify()

class ECDSA(unittest.TestCase):
    def setUp(self):
        with open('tests/poc/test-ec.pem', mode='rb') as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = None,
                backend = openssl
            )
            self._public_key = self._private_key.public_key()

    def test_ecdsa_sign_verify(self):
        message = b'test'

        signer = self._private_key.signer(
            ec.ECDSA(
                hashes.SHA256()
            )
        )
        signer.update(message)
        signature = signer.finalize()

        verifier = self._public_key.verifier(
            signature,
            ec.ECDSA(
                hashes.SHA256()
            )
        )
        verifier.update(message)
        self.assertTrue(verifier.verify())

    def test_ecdsa_verify(self):
        pass

if __name__ == '__main__':
    unittest.main()
