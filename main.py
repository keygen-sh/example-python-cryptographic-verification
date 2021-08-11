from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import ed25519
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

  @staticmethod
  def gray(x):
    return '\033[34m%s\033[0m' % x

# Cryptographically verify license key using the provided scheme and public key
def verify_license_key(license_scheme, license_key):
  assert license_scheme in ('ED25519_SIGN', 'RSA_2048_PKCS1_SIGN_V2', 'RSA_2048_PKCS1_PSS_SIGN_V2'), 'scheme %s not supported or is missing' % license_scheme
  assert license_key, 'license key is missing'

  # Split license key to obtain key and signature, then decode base64url encoded values
  signing_data, enc_sig = license_key.split(".")
  prefix, enc_key       = signing_data.split("/")
  assert prefix == 'key', 'license key prefix %s is invalid' % prefix

  sig = base64.urlsafe_b64decode(enc_sig)
  key = base64.urlsafe_b64decode(enc_key)

  if license_scheme == 'ED25519_SIGN':
    ok = verify_ed25519(license_scheme, sig, ("key/%s" % enc_key).encode())
  else:
    ok = verify_rsa(license_scheme, sig, ("key/%s" % enc_key).encode())

  if ok:
    print('%s License key contents: %s' % (Color.gray('[INFO]'), key))

  return ok

# Cryptographically verify the license key using RSA
def verify_ed25519(license_scheme, sig, msg):
  assert license_scheme in ('ED25519_SIGN'), 'scheme %s must be Ed25519' % license_scheme

  # Load the hex-encoded verify key from the env
  verify_key = ed25519.VerifyingKey(
    os.environ['KEYGEN_PUBLIC_KEY'].encode(),
    encoding='hex'
  )

  # Verify the license
  try:
    verify_key.verify(sig, msg)

    return True
  except ed25519.BadSignatureError:
    return False

# Cryptographically verify the license key using RSA
def verify_rsa(license_scheme, sig, msg):
  assert license_scheme in ('RSA_2048_PKCS1_SIGN_V2', 'RSA_2048_PKCS1_PSS_SIGN_V2'), 'scheme %s not supported by RSA' % license_scheme

  # Load the PEM formatted public key from the env
  pub_key = serialization.load_pem_public_key(
    os.environ['KEYGEN_PUBLIC_KEY'].encode(),
    backend=default_backend()
  )

  # Choose the correct padding based on the chosen scheme
  if license_scheme == 'RSA_2048_PKCS1_PSS_SIGN_V2':
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
      msg,
      pad,
      hashes.SHA256()
    )

    return True
  except (InvalidSignature, TypeError):
    return False

try:
  ok = verify_license_key(
    sys.argv[1],
    sys.argv[2]
  )
except AssertionError as e:
  print('%s %s' % (Color.red('[ERROR]'), e))

  sys.exit(1)
except Exception as e:
  print('%s cryptography: %s' % (Color.red('[ERROR]'), e))

  sys.exit(1)

if ok:
  print('%s License key is authentic!' % Color.green('[OK]'))

  sys.exit(0)
else:
  print('%s License key is not authentic!' % Color.red('[ERROR]'))

  sys.exit(1)
