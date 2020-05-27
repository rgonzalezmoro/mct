from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Crypto.Signature import pss
from funcHash import itemHash

import sys
import os

from funcRSA import isPrivateKey, isPublicKey, isRSA

# import environ

# Se usa la clase cuando hay que guardar un hash serializado en BBDD
# Si no se hace así no se puede recuperar el tipo SHA3_256 cuando se lee el hash de la BBDD

class hashClass(object):
    def __init__(self, _string, _long):
        self.string = _string
        self.long = _long
        
    @property
    def hash(self):
        return itemHash(self.string, self.long)
    
    def signHash(self, _priv_key):
        try:
            # isPrivateKey valida que se trata de un objeto RSA
            assert isPrivateKey(_priv_key)
        except AssertionError:
            sys.exit('Se esperaba recibir una clave publica RSA')
     
        try:
            signedObject = pss.new(_priv_key).sign(self.hash)
            return signedObject  
        except:
            sys.exit('Error al firmar el objeto')

    def verifySign(self, _pub_key, _sign):
        try:
            # isPublicKey valida que se trata de un objeto RSA
            assert isPublicKey(_pub_key)
        except AssertionError:
            sys.exit('Se esperaba recibir una clave publica RSA')

        try:
            verifier = pss.new(_pub_key)
            verifier.verify(self.hash, _sign)
            return True
        except ValueError:
            return False
