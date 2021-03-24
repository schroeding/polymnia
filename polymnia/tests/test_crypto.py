import unittest
import polymnia.core.io
import polymnia.core.tls
import cryptography
import polymnia.core.router
import polymnia.protocol
import polymnia.protocol.layer2


class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.testStr = 'Als Gregor Samsa eines Morgens aus unruhigen Träumen erwachte, fand er sich in seinem Bett zu einem ungeheuren Ungeziefer verwandelt. '\
            'Er lag auf seinem panzerartig harten Rücken und sah, wenn er den Kopf ein wenig hob, seinen gewölbten, braunen, von bogenförmigen Versteifungen '\
            'geteilten Bauch, auf dessen Höhe sich die Bettdecke, zum gänzlichen Niedergleiten bereit, kaum noch erhalten konnte. Seine vielen, im Vergleich '\
            'zu seinem sonstigen Umfang kläglich dünnen Beine flimmerten ihm hilflos vor den Augen.'

    def testIO(self):
        self.assertFalse(polymnia.core.io.writeData('tests/../../../data', 'file1', self.testStr.encode('utf-8'), 'txt'))
        self.assertFalse(polymnia.core.io.writeData('', '', self.testStr.encode('utf-8'), '/../'))
        self.assertTrue(polymnia.core.io.writeData('tests/data', 'file1', self.testStr.encode('utf-8'), 'txt'))
        self.assertIsNone(polymnia.core.io.readData('invalidinvalidinvalidinvalidinvalid'))
        self.assertIsNone(polymnia.core.io.readData('tests/../../../../../../../../etc/passwd'))
        self.assertEqual(polymnia.core.io.readData('data/tests/data/file1_300b3ab9a493a9e24594ec5558bdc5a25cadfec7918301183bee0fd14e79b6ab.txt'), self.testStr.encode('utf-8'))


    def testRSA(self):
        self.assertFalse(polymnia.core.tls.generateRSAKey('test', 256))
        self.assertTrue(polymnia.core.tls.generateRSAKey('test', 512))
        self.assertTrue(polymnia.core.tls.generateRSAKey('test', 1024))
        self.assertTrue(polymnia.core.tls.generateRSAKey('test', 2048))
        self.assertTrue(polymnia.core.tls.generateRSAKey('test', 4096))
        self.assertIsInstance(polymnia.core.tls.getRSAKey('test'), cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization)
        self.assertTrue(polymnia.core.tls.dumpKey('test'))


    def testX509(self):
        self.assertTrue(polymnia.core.tls.generateCaCertificate('test', 'test ca'))
        self.assertIsInstance(polymnia.core.tls.getCACertificate('test'), cryptography.x509.Certificate)
        self.assertTrue(polymnia.core.tls.dumpCaCertificate('test'))
        self.assertTrue(polymnia.core.tls.cloneCaCertificate('test_copy', polymnia.core.io.readData('polymnia/tests/sample_data/DFN_CA_Certificate.crt', True)))
        self.assertTrue(polymnia.core.tls.dumpCaCertificate('test_copy'))
