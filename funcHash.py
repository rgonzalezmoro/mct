from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Crypto.Signature import pss

from funcRSA import isPrivateKey, isPublicKey

import sys
import os

# import environ

# Se usa la clase cuando hay que guardar un hash serializado en BBDD
# Si no se hace así no se puede recuperar el tipo SHA3_256 cuando se lee el hash de la BBDD

# Hace un hash del objeto que recibe

valid_hash = [
    SHA3_224.SHA3_224_Hash,
    SHA3_256.SHA3_256_Hash,
    SHA3_384.SHA3_384_Hash,
    SHA3_512.SHA3_512_Hash
]

def itemHash(objectToHash, size):
    def switch_dict(size):
        return {
            224: SHA3_224.new(objectToHash.encode('utf-8')),
            256: SHA3_256.new(objectToHash.encode('utf-8')),
            384: SHA3_384.new(objectToHash.encode('utf-8')),
            512: SHA3_512.new(objectToHash.encode('utf-8'))
        }.get(size, None)

    if not isinstance(objectToHash,str):
        # sys.exit('No se ha recibido un tipo string') 
        sys.exc_info()[2] 
    if not isinstance(size,int):
        sys.exit('Se esparaba recibir un entero como longitud de clave') 
    try:
        h = switch_dict(size)
        if not h: raise ValueError
        return h
    except ValueError:
        sys.exit('Error en tamaño de clave de salida. Validas 224,256,384,512')
    except:
        sys.exit('Error interno en libreria Crypto.Hash'.format(size))

"""
Despues de mucho chacharreo, llego a la conclusión que hay que recibir un hash y no 
un string para hashear. Los hash nunca son iguales, lo que son iguales son los hexdigest()
"""
def signHash(inPrivKey, inHash):
    if inHash.__class__ not in valid_hash : 
        sys.exit('Se esperaba recibir un hash')

    if isPrivateKey(inPrivKey):
        try:
            signedObject = pss.new(inPrivKey).sign(inHash)
            return signedObject  
        except:
            sys.exit('Error al firmar el objeto')
    else:
        sys.exit('La clave pasada como parámetro no puede ser usada para firmar')

# Verifica si una firma hecha con una clave privada es correcta comprobando 
# con la publica que se recibe como parámetro
def verifySign(inPubKey, inHash, inSignedHash): 
    if not isPublicKey(inPubKey):
            sys.exit('Se esperaba recibir una clave pública')
    
    if inHash.__class__ not in valid_hash : 
        sys.exit('Se esperaba recibir un hash')
    if not isinstance(inSignedHash, bytes):
        sys.exit('La firma tiene que tener formato binario')

    try:
        verifier = pss.new(inPubKey)
        verifier.verify(inHash, inSignedHash)
        return True
    except:
        return False