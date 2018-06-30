# Spectral AEAD

Spectral is algorithm for authenticated encryption with associated data; it uses [Speck](https://csrc.nist.gov/csrc/media/events/lightweight-cryptography-workshop-2015/documents/papers/session1-shors-paper.pdf) in [CTR mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) as the underlying cipher (with a 128-bit block size and a 128-bit key size) along with [HMAC](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.198-1.pdf)-[SHA256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) in an [Encrypt-then-MAC](https://www.iso.org/standard/46345.html) construction.

This package provides tested, performant **Python 3** CFFI bindings to an implementation of Spectral, including abstractions for simplified encryption and decryption.

# Installation

You can install this package using `pip` or the included `setup.py` script:

    # Using pip
    pip install spectral-aead
    
    # Using setup.py
    python setup.py install

# Usage

```python
from spectral import *

# Demonstration key, nonce, plaintext and associated data
key = b"\0" * spectral.KEY_SIZE
nonce = b"\0" * spectral.NONCE_SIZE
plaintext = b"\0" * 16
associated = b"\0" * 16

# Spectral simplified encryption
encrypted = encrypt(key, plaintext, associated)  # Associated data is optional

# Spectral simplified decryption
computed_plaintext = decrypt(key, encrypted, associated)  # Raises RuntimeError if any parameter has been tampered with
assert plaintext == computed_plaintext

# Spectral disjoint encryption
ciphertext, mac = encrypt_disjoint(key, nonce, plaintext, associated)  # Associated data is optional

# Spectral disjoint decryption
computed_plaintext = decrypt_disjoint(key, nonce, ciphertext, mac, associated)  # Raises RuntimeError if any parameter has been tampered with
assert plaintext == computed_plaintext
```

# License
```text
BSD 3-Clause License

Copyright (c) 2018, Phil Demetriou
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```