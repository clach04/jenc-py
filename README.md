# jenc-py

  * Working - jenc/Markor decrypt/encrypt library
      * API Work-In-Progress, needs a buffer API
  * Not yet working - tool

The aim is to have a pure python (with crypto dependencies) [jenc](https://github.com/opensource21/jpencconverter) (as used by [Markor](https://github.com/gsantner/markor)) decrypt/encrypt library.


Test jenc file https://github.com/opensource21/jpencconverter/blob/master/src/test/encrypted/Test3.md.jenc
Test password `geheim` from https://github.com/opensource21/jpencconverter/blob/master/src/test/resources/application.properties


## Getting Started

### Regular install

    pip install jenc

### Without a source code checkout

Picking up the latest version

    pip uninstall jenc; python -m pip install --upgrade git+https://github.com/clach04/jenc.git

### From a source code checkout

    # pip uninstall jenc
    # python -m pip install -r requirements.txt
    # TODO requirements_optional.txt
    python -m pip install -e .

## Examples

### Example Encrypt / Decrypt in memory

    import jenc

    password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
    encrypted_bytes = jenc.encrypt(password, b"Hello World")
    plaintext_bytes = jenc.decrypt(password, encrypted_bytes)


## jenc file format

There are multiple versions V001 (and the old U001).

File format:

  * 4 bytes - define the version.
  * nonce bytes - bytes as nonce for cipher depends. The length depends on the version.
  * salt bytes - bytes to salt the password. The length depends on the version.
  * content bytes - the encrypted content-bytes.

From the original Java code for jpencconverter it appears that strings are converted to/from UTF-8 (i.e. passwords and plaintext).

### jenc file format - V001

From Python code:

    # note CamelCase to match https://github.com/opensource21/jpencconverter/blob/f65b630ea190e597ff138d9c1ffa9409bb4d56f7/src/main/java/de/stanetz/jpencconverter/cryption/JavaPasswordbasedCryption.java#L229
    'keyFactory': 'PBKDF2WithHmacSHA512',
    'keyIterationCount': 10000,  # this is probably too small/few in 2024
    'keyLength': 256,
    'keyAlgorithm': 'AES',
    'keySaltLength': 64,  # in bytes
    'cipher': 'AES/GCM/NoPadding',
    'nonceLenth': 32,  # nonceLenth (sic.) == Nonce Length  # in bytes
