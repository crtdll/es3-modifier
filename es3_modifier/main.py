from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad, pad
from Crypto.Hash import SHA1
import json, re

class DecryptionException(Exception):
  "Raised when the decryption fails, likely due to the wrong key"
  pass

class InvalidDataException(Exception):
  "Raised when the decrypted data is not in the ES3 format"
  pass

def decrypt_aes_128_cbc(data, password):
  salt = data[:16]
  key = PBKDF2(password, salt, dkLen=16, count=100, hmac_hash_module=SHA1)
  cipher = AES.new(key, AES.MODE_CBC, IV=salt)
  decrypted_data = cipher.decrypt(data[16:])
  unpadded_data = unpad(decrypted_data, AES.block_size)
  return unpadded_data

def encrypt_aes_128_cbc(data, password, salt):
  key = PBKDF2(password, salt, dkLen=16, count=100, hmac_hash_module=SHA1)
  cipher = AES.new(key, AES.MODE_CBC, IV=salt)
  padded_data = pad(data, AES.block_size)
  encrypted_data = cipher.encrypt(padded_data)
  return salt + encrypted_data

def demangle_type(type_str):
  primary_type_match = re.search(r'(\w+)\`', type_str)
  primary_type = primary_type_match.group(1) if primary_type_match else None

  inner_types_matches = re.findall(r'\[([\w+]+\.)*?([\w+]+),', type_str)
  inner_types = [match[1].replace('+', '.') for match in inner_types_matches]
  
  if primary_type and inner_types:
    return f"{primary_type}<{', '.join(inner_types)}>"
  return type_str

class ES3:
  def __init__(self, data, key) -> None:
    self.key = key
    self.data = data
    self.jobj = None
    
  def __beautify(self, d):
    for key, value in d.items():
      if key == '__type' and 'System.' in value:
        d[key] = demangle_type(value)
      elif isinstance(value, dict):
        self.__beautify(value)
    return d
    
  def beautify(self):
    if self.jobj is None:
      return ''
    o = self.jobj
    return self.__beautify(o)
    
  def load(self):
    try:
      decrypted = decrypt_aes_128_cbc(self.data, self.key)
      try:
        self.jobj = json.loads(decrypted)
        return self.jobj
      except:
        raise InvalidDataException('Decrypted data was not in a valid ES3 format. Wrong key?')
    except ValueError as e:
      raise DecryptionException(f'AES: {e} Wrong key?')
    
  def save(self, raw_data: str) -> bytes:
    try:
      return encrypt_aes_128_cbc(raw_data.encode(), self.key, self.data[:16])
    except ValueError as e:
      raise DecryptionException(f'AES: {e} Wrong key?')