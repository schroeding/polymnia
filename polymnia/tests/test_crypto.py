import unittest
import polymnia
import cryptography


class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.testStr = 'Als Gregor Samsa eines Morgens aus unruhigen Träumen erwachte, fand er sich in seinem Bett zu einem ungeheuren Ungeziefer verwandelt. '\
            'Er lag auf seinem panzerartig harten Rücken und sah, wenn er den Kopf ein wenig hob, seinen gewölbten, braunen, von bogenförmigen Versteifungen '\
            'geteilten Bauch, auf dessen Höhe sich die Bettdecke, zum gänzlichen Niedergleiten bereit, kaum noch erhalten konnte. Seine vielen, im Vergleich '\
            'zu seinem sonstigen Umfang kläglich dünnen Beine flimmerten ihm hilflos vor den Augen.'

    def testIO(self):
        self.assertTrue(polymnia.core.io.writeData('tests/data', 'file1', self.testStr.encode('utf-8'), 'txt'))
        self.assertEqual(polymnia.core.io.readData('tests/data/file1_044435a5149851f4fcb2f6ad5628a27f9ef9c3e8.txt'), self.testStr.encode('utf-8'))
        
        self.assertTrue(polymnia.core.tls.generateRSAKey('test', 1024))
        self.assertIsInstance(polymnia.core.tls.getRSAKey('test'), cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization)
        self.assertTrue(polymnia.core.tls.dumpKey('test'))