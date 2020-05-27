import os

# Las variables de entrono deberían ir en bash.profile pero para no andar tocando
# las defino con os.environ

""" Variables de entorno cuando se hacen pruebas ejecutando ANACONDA crypto_develop que usa PyCryptodome """
os.environ['CIPHER_KEY']='21ba60ee21e60988421329cb8a957170c7d532f2f12b07ff1efec0a9ffedb7d3'
os.environ['FILES_PATH']='/Users/rafaelgonzalez/projects/source/jupyter_files/crypto_mct/files/'
os.environ['MCT_PATH']='/Users/rafaelgonzalez/projects/source/modulos/crypto/utilsMCT'
os.environ['BBDD_PATH']='/Users/rafaelgonzalez/projects/source/crypto_blockchain/bbdd/'
os.environ['DEFAULT_EXTENSION']='.pem'
os.environ['VALID_CHARS']='abc123'
os.environ['STRING_LONG']='6'
os.environ['DIFFICULTY']='1'


