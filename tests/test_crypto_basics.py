import unittest

import cryptography.hazmat.backends.openssl.backend as openssl
import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.hashes as hashes

class HashTestCases(unittest.TestCase):
    def testSHA1(self):
        digest = hashes.Hash(hashes.SHA1(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(digest.finalize().hex(), 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3')

    def testSHA256(self):
        digest = hashes.Hash(hashes.SHA256(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(digest.finalize().hex(), '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')

    def testSHA384(self):
        digest = hashes.Hash(hashes.SHA384(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(digest.finalize().hex(), '768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9')

    def testSHA512(self):
        digest = hashes.Hash(hashes.SHA512(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(digest.finalize().hex(), 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff')

class RSATestCases(unittest.TestCase):
    def setUp(self):
        self._private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 2048,
            backend = openssl
        )
        self._public_key = self._private_key.public_key()

    def testEncryptDecrypt(self):
        message = b'test'
        ciphertext = self._public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        plaintext = self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        self.assertEqual(plaintext, message)

class ECDSA(unittest.TestCase):
    def setUp(self):
        self._private_key = ec.generate_private_key(
            curve = ec.SECP384R1(),
            backend = openssl
        )
        self._public_key = self._private_key.public_key()

    def testSignVerify(self):
        message = b'test'
        signer = self._private_key.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(message)
        signature = signer.finalize()

        verifier = self._public_key.verifier(signature,ec.ECDSA(hashes.SHA256()))
        verifier.update(message)
        self.assertTrue(verifier.verify())


if __name__ == '__main__':
    unittest.main()
