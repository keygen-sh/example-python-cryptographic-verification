# Example Python Cryptographic Verification
This is an example of cryptographically verifying a license key's authenticity,
and extracting embedded tamper-proof data within the key for offline use, all by
using your Keygen account's public key. You can find your public keys within
[your account's settings page](https://app.keygen.sh/settings).

This example implements the `ED25519_SIGN`, `RSA_2048_PKCS1_SIGN_V2` and `RSA_2048_PKCS1_PSS_SIGN_V2`
[cryptographic signing schemes](https://keygen.sh/docs/api/#policies-create-attrs-scheme).
Cryptographically verifying schemed licenses can be used to implement
offline licensing, as well as to add additional security measures to
your licensing model. All that is needed to cryptographically verify
a license is your account's public key.

## Running the example

First up, add an environment variable containing your public key:
```bash
export KEYGEN_PUBLIC_KEY='799efc7752286e6c3815b13358d98fc0f0b566764458adcb48f1be2c10a55906'
```

You can either run each line above within your terminal session before
starting the app, or you can add the above contents to your `~/.bashrc`
file and then run `source ~/.bashrc` after saving the file.

Next, install dependencies with [`pip`](https://packaging.python.org/):

```
pip install -r requirements.txt
```

Then run the script, passing in the `scheme` and `key` as arguments:

```bash
python main.py 'ED25519_SIGN' 'key/{SIGNED_LICENSE_KEY}'
```

The license key's authenticity will be verified using Ed25519, or RSA-SHA256 with
the given padding scheme. Be sure to copy your public key and license key correctly - your
keys will fail validation if these are copied or included incorrectly. You can
find your public keys in [your account's settings](https://app.keygen.sh/settings).

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
