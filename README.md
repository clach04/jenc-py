# jenc-py

jenc/Markor decrypt/encrypt library

https://github.com/clach04/jenc-py

**IMPORTANT** before using the optionally encryption features,
ensure that it is legal in your country to use the specific encryption ciphers.
Some countries have also have restrictions on import, export, and usage see http://www.cryptolaw.org/cls-sum.htm

The aim is to have a pure python (with crypto dependencies) library that is able to read/write .jenc files as used by [Markor](https://github.com/gsantner/markor)
which uses the [jenc](https://github.com/opensource21/jpencconverter) format decrypt/encrypt Java library.

  * [Getting Started](#getting-started)
    + [Regular install](#regular-install)
    + [Without a source code checkout](#without-a-source-code-checkout)
    + [From a source code checkout](#from-a-source-code-checkout)
  * [Examples](#examples)
    + [Command line Encrypt / Decrypt](#command-line-encrypt---decrypt)
      - [Command line Decrypt](#command-line-decrypt)
      - [Command line Encrypt](#command-line-encrypt)
    + [Example Encrypt / Decrypt in memory](#example-encrypt---decrypt-in-memory)
  * [jenc file format](#jenc-file-format)
    + [jenc file format - V001](#jenc-file-format---v001)
    + [jenc file format - U001](#jenc-file-format---u001)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>


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

#### Run test suite

    python -m jenc.tests.testsuite
    python -m jenc.tests.testsuite -v

## Examples

### Command line Encrypt / Decrypt

Help:

    Usage: [options] in_filename

    Command line tool to encrypt/decrypt; .jenc / Markor / jpencconverter files

    Options:
      --version             show program's version number and exit
      -h, --help            show this help message and exit
      -o FILE, --output=FILE
                            write output to FILE
      -d, --decrypt         decrypt in_filename
      -e, --encrypt         encrypt in_filename
      -E ENVVAR, --envvar=ENVVAR
                            Name of environment variable to get password from
                            (defaults to JENC_PASSWORD) - unsafe
      -p PASSWORD, --password=PASSWORD
                            password, if omitted but OS env JENC_PASSWORD is set
                            use that, if missing prompt - unsafe
      -P PASSWORD_FILE, --password_file=PASSWORD_FILE
                            file name where password is to be read from, trailing
                            blanks are ignored
      -j JENC_VERSION, --jenc-version=JENC_VERSION, --jenc_version=JENC_VERSION
                            jenc version to use, case sensitive
      -v, --verbose
      -s, --silent          if specified do not warn about stdin using


#### Command line Decrypt

To stdout

    # Test V001 file from jpencconverter
    python -m jenc -p geheim jenc\tests\data\Test3.md.jenc

To a file named `output.txt`

    python -m jenc -p geheim jenc\tests\data\Test3.md.jenc -o output.txt


#### Command line Encrypt

Encrypt stdin, into `output.txt.jenc`

    echo hello| python -m jenc --encrypt -p geheim - -o output.txt.jenc
    echo hello| python -m jenc -e        -p geheim - -o output.txt.jenc

### Example Encrypt / Decrypt in memory

Test jenc file https://github.com/opensource21/jpencconverter/blob/master/src/test/encrypted/Test3.md.jenc
Test password `geheim` from https://github.com/opensource21/jpencconverter/blob/master/src/test/resources/application.properties

    import jenc

    password = 'geheim'  # same password used in demos for Java version https://github.com/opensource21/jpencconverter/tree/master/src/test/encrypted
    encrypted_bytes = jenc.encrypt(password, b"Hello World")
    plaintext_bytes = jenc.decrypt(password, encrypted_bytes)


## jenc file format

There are multiple versions V001 (and the old U001).

TL;DR [AES-256-GCM (No Padding)](https://en.wikipedia.org/wiki/Galois/Counter_Mode), using KDF [pbkdf2-hmac-sha512](https://en.wikipedia.org/wiki/PBKDF2) with 10000 iterations.

File format:

  * 4 bytes - define the version.
  * nonce bytes - bytes as nonce for cipher depends. The length depends on the version. 32-bytes for latest version.
  * salt bytes - bytes to salt the password. The length depends on the version. 64-bytes for latest version.
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
    'nonceLenth': 32,  # nonceLenth (sic.) == Nonce Length, i.e. IV length # in bytes

### jenc file format - U001

From Python code:

    'U001': {  # NOTE Deprecated, i.e. not recommended
        'keyFactory': JENC_PBKDF2WithHmacSHA1,
        'keyIterationCount': 10000,  # this is probably too small/few in 2024
        'keyLength': 256,
        'keyAlgorithm': 'AES',
        'keySaltLength': 64,  # in bytes
        'cipher': JENC_AES_GCM_NoPadding,
        'nonceLenth': 32,  # nonceLenth (sic.) == Nonce Length, i.e. IV length  # in bytes
