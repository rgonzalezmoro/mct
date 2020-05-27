from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

import json
import sys
import os

# environ.py contiene las variables de entorno
import environ

def setRSAkey(*params):
    
    if len(params) == 2 or len(params) > 3: 
        sys.exit('Error en el número de parámetros de llamada. Deben ser uno o tres')
    
    if len(params) == 1:
        _lenght = params[0]
        _length = (lambda x : _lenght if type(x) is int and x in (1024,2048,3072,7680,15360) else sys.exit('Longitud de la clave errónea o tipo incorrecto'))(_lenght)
    
    if len(params) == 3:
        _lenght, _name, _cipher = params
        _name = (lambda x : _name if type(x) is str else sys.exit('Se esperaba un string en el segundo parametro'))(_name)
        _cipher = (lambda x : _cipher if type(x) is bool else sys.exit('Se esperaba un boolean en el tercer parámetro'))(_cipher)

    key = RSA.generate(_lenght)
    
    if len(params) == 1: 
        return key

    path = os.getenv('FILES_PATH')
    file = ''.join([_name, os.getenv('DEFAULT_EXTENSION')])

    if _cipher:
        jsonFile = cipherCTR(key)
        try: 
            with open(os.path.join(path,file), "wb") as c:
                c.write(bytearray(jsonFile.encode('utf-8')))
                return key
        except:
            sys.exit('Error al guardar fichero con la clave cifrada')
    else:
        try: 
            with open(os.path.join(path,file), "wb") as c:
                c.write(bytearray(key.export_key()))
                return key
        except:
            sys.exit('Error al guardar fichero con la clave serializada')

    return key
# -----------------------------------------------------------------------------------------
# Recibe un fichero y su extensión (pem) 
# Lee el fichero y comprueba si tiene formato diccionario JSON, empieza por '{' y termina por '}'
# En caso afirmativo hay que descfrar la clave de cipherprivate y en caso contrario (AssertionError) 
# se hace un importKey sin descrifrar
def getRSAkey(_file): # Solo se recibe el nombre del fichero
    if not isinstance(_file, str):
        sys.exit('Se esperaba un string como nombre de fichero')

    path = os.getenv('FILES_PATH')
    file = ''.join([_file, os.getenv('DEFAULT_EXTENSION')]) 

    if os.access(os.path.join(path,file), os.R_OK):       
        try:  
            with open(os.path.join(path,file), "r") as f:
                json_read = f.read()
        except:
            sys.exit('Error al abrir el fichero {}'.format(file))
    else:
        sys.exit('No existe se encontro el fichero {} en la ruta {}'.format(file, path))

    try: 
        assert json_read.startswith('{') and json_read.endswith('}') # Es un fichero cifrado. String que dentro tiene el diccionario
        return RSA.importKey(decipherCTR(json_read))
    except AssertionError: 
        return RSA.importKey(json_read.encode('utf-8'))

# -----------------------------------------------------------------------------------------
# Devuelve un JSON con la clave privada en el campo 'cipherprivate'. La clave está cifrada con AES256
# El procedimiento que llama debe salvar el JSON a fichero
def cipherCTR(inRSA): 
    try:
        assert isRSA(inRSA)
        key = bytearray.fromhex(os.getenv('CIPHER_KEY'))
        try: 
            cipher = AES.new(key, AES.MODE_CTR)
            nonce = b64encode(cipher.nonce).decode('utf-8')
            
            priv_bytes = cipher.encrypt(inRSA.exportKey())
            cipher_private = b64encode(priv_bytes).decode('utf-8')
        
            return json.dumps({'nonce':nonce, 'cipherprivate':cipher_private})
        except:
            sys.exit('Error en el cifrado AES')
    except AssertionError:
        sys.exit('Se esperaba una clave RSA para cifrar y se recibió un {}'.format(inRSA.__class__))
# -----------------------------------------------------------------------------------------
# Recibo un fichero JSON y devuelve el campo 'cipherprivate' descrifrado
# Devuelve la clave privada en tipo bytes
def decipherCTR(_json_read):
    key = bytearray.fromhex(os.getenv('CIPHER_KEY'))
    try:
        json_b64 = json.loads(_json_read)
        nonce = b64decode(json_b64['nonce'])
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        cipherprivate = b64decode(json_b64['cipherprivate'])      
        privateRSA = cipher.decrypt(cipherprivate)
        return privateRSA # No es objeto RSA. getRSAkey tiene que hacer el importKey
    except:
        sys.exit('Error al descifrar AES256')

# -----------------------------------------------------------------------------------------
# True si es un objeto RSA        
def isRSA(_object):
    return True if _object.__class__ == RSA.RsaKey else False

# -----------------------------------------------------------------------------------------
# True si es una clave privada        
def isPrivateKey(_key):
    try:
        assert isRSA(_key)
        return _key.has_private()
    except AssertionError:
        sys.exit('Se esperaba un objeto RSA')

# -----------------------------------------------------------------------------------------
# True si es una clave publica        
def isPublicKey(_key):
    try:
        assert isRSA(_key)
        return True if not _key.has_private() else False
    except AssertionError:
        sys.exit('Se esperaba un objeto RSA')

# -----------------------------------------------------------------------------------------
# Para poder guardar en BBDD hay que generar un tipo byte (binario)
def serializeKey(_key):
    return _key.exportKey() if isRSA(_key) else sys.exit('Se esperaba un objeto RSA')

# -----------------------------------------------------------------------------------------
# Si se ha guardado una clave en BBDD con exportKey hay que convertirla a
# objeto RSA para poder usarla
def deSerializeKey(_key_bytes):
    return RSA.importKey(_key_bytes) if isinstance(_key_bytes, bytes) else sys.exit('Se esperaba un objeto binario/bytes')

    
        