'''
Test various DNSSEC cryptography primatives
'''

import unittest
import json

import cryptography.hazmat.backends.openssl.backend as openssl
import cryptography.hazmat.primitives.asymmetric.ec as ec
# import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes


class HashTestCases(unittest.TestCase):
    '''
    Test hashing algorithms used in DNSSEC
    '''

    def setUp(self):
        '''
        Load JSON file of known hashes of the 'test' word
        '''
        with open('tests/poc/test_crypto_basics.json') as hashes_file:
            self._hashes = json.load(hashes_file)

    def test_hash_sha1(self):
        '''
        Test hashing known string with SHA1 hash
        '''
        digest = hashes.Hash(hashes.SHA1(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(
            digest.finalize().hex(),
            self._hashes['sha1']
        )

    def test_hash_sha256(self):
        '''
        Test hashing known string with SHA256 hash
        '''
        digest = hashes.Hash(hashes.SHA256(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(
            digest.finalize().hex(),
            self._hashes['sha256']
        )

    def test_hash_sha384(self):
        '''
        Test hashing known string with SHA384 hash
        '''
        digest = hashes.Hash(hashes.SHA384(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(
            digest.finalize().hex(),
            self._hashes['sha384']
        )

    def test_hash_sha512(self):
        '''
        Test hashing known string with SHA512 hash
        '''
        digest = hashes.Hash(hashes.SHA512(), backend=openssl)
        digest.update(b'test')
        self.assertEqual(
            digest.finalize().hex(),
            self._hashes['sha512']
        )


class RSATestCases(unittest.TestCase):
    '''
    Test RSA algorithms
    '''

    def setUp(self):
        '''
        Test loading PKCS8 file, generated externally by OpenSSL.
        Loads pre-generated RSA signatures for comparison in tets
        '''
        with open('tests/poc/test-rsa.pem', mode='rb') as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=openssl
            )
            self._public_key = self._private_key.public_key()

        with open('tests/poc/test_crypto_basics.json') as signature_file:
            self._signatures = json.load(signature_file)

    def test_rsa_sign(self):
        '''
        Test signing of message, using RSA and PKCS1v15 padding,
        which provides a consistent result.
        '''
        message = b'test'
        signature = bytes.fromhex(
            self._signatures['rsasig']
        )

        signer = self._private_key.signer(
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signer.update(message)
        self.assertEqual(signer.finalize(), signature)

    def test_rsa_verify(self):
        '''
        Verify signature, using RSA, and PKCS1v15 padding,
        which provides a consistent result.
        '''
        message = b'test'
        signature = bytes.fromhex(
            self._signatures['rsasig']
        )

        verifier = self._public_key.verifier(
            signature,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        verifier.update(message)
        verifier.verify()


class ECDSA(unittest.TestCase):
    '''
    Test Elliptic Curve DSA algorithms
    '''

    def setUp(self):
        '''
        Test loading PKCS8 file, generated externally by OpenSSL
        '''
        with open('tests/poc/test-ec.pem', mode='rb') as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=openssl
            )
            self._public_key = self._private_key.public_key()

    def test_ecdsa_sign_verify(self):
        '''
        Test Elliptic Curve DSA signing of message, and then verification.
        Unable to split in to separate sign, and verify steps due to some time based code
        '''
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

if __name__ == '__main__':
    unittest.main()
