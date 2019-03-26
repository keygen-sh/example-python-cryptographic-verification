from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
import sys
import os

# Add ANSII color codes to console output
if sys.platform.lower() == 'win32':
  os.system('color')

class Color():
  @staticmethod
  def red(x):
    return '\033[31m%s\033[0m' % x

  @staticmethod
  def green(x):
    return '\033[32m%s\033[0m' % x

# Cryptographically verify license key using the provided scheme and public key
def verify_license_key(license_scheme, license_key):
  assert license_scheme in ('RSA_2048_PKCS1_SIGN', 'RSA_2048_PKCS1_PSS_SIGN'), 'scheme %s not supported or is missing' % license_scheme
  assert license_key, 'license key is missing'

  # Split license key to obtain key and signature, then decode base64url encoded values
  enc_key, enc_sig = license_key.split(".")
  key = base64.urlsafe_b64decode(enc_key)
  sig = base64.urlsafe_b64decode(enc_sig)

  # Load the PEM formatted public key from the environment
  pub_key = serialization.load_pem_public_key(
    bytes(os.environ['KEYGEN_PUBLIC_KEY']),
    backend=default_backend()
  )

  # Choose the correct padding based on the chosen scheme
  if license_scheme == 'RSA_2048_PKCS1_PSS_SIGN':
    pad = padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH
    )
  else:
    pad = padding.PKCS1v15()

  # Verify the license
  try:
    pub_key.verify(
      sig,
      key,
      pad,
      hashes.SHA256()
    )

    return True
  except (InvalidSignature, TypeError):
    return False

arg_names = ['program', 'license_scheme' ,'license_key']
args = map(None, arg_names, sys.argv)
args = { k: v for (k, v) in args }

try:
  ok = verify_license_key(args['license_scheme'], args['license_key'])
except AssertionError as e:
  print('%s %s' % (Color.red('[ERROR]'), e.message))

  sys.exit(1)
except Exception as e:
  print('%s cryptography: %s' % (Color.red('[ERROR]'), e.message))

  sys.exit(1)

if ok:
  print('%s License key is authentic!' % Color.green('[OK]'))

  sys.exit(0)
else:
  print('%s License key is not authentic!' % Color.red('[ERROR]'))

  sys.exit(1)