#!/usr/bin/env python
# -*- coding: ascii -*-
# vim:ts=4:sw=4:softtabstop=4:smarttab:expandtab
"""Python jpencconverter jenc library
Copyright (C) 2024 Chris Clark (clach04)

https://github.com/clach04/jenc-py

Original Java version https://github.com/opensource21/jpencconverter and
https://gitlab.com/opensource21/jpencconverter
"""

import sys
import os
import platform

try:
    from setuptools import setup, find_packages
except ImportError:
    # NOTE distutils supposed to be removed from Python 3.12
    from distutils.core import setup
    find_packages = None

from distutils.util import get_platform

try:
    from docutils.core import publish_cmdline
except ImportError:
    publish_cmdline = None


is_win = sys.platform.startswith('win')
is_cpython = platform.python_implementation() == 'CPython'


readme_filename = 'README.md'
if os.path.exists(readme_filename):
    f = open(readme_filename)
    long_description = f.read()
    f.close()
else:
    long_description = None


if len(sys.argv) <= 1:
    print("""
Suggested setup.py parameters:

    * build
    * install
    * sdist  --formats=zip
    * sdist  # NOTE requires tar/gzip commands


    python -m pip install -e .

PyPi:

    python -m pip install setuptools twine

    python setup.py sdist
    # python setup.py sdist --formats=zip
    python -m twine upload dist/* --verbose

    ./setup.py  sdist ; twine upload dist/* --verbose

""")


# Metadata
project_name = 'jenc'
project_name_lower = project_name.lower()
description = 'Python jenc jpencconverter encryption implementation'
license = "Apache Software License"  # ensure this matches tail of http://pypi.python.org/pypi?%3Aaction=list_classifiers


__version__ = None  # Overwritten by executing _version.py.
exec(open(os.path.join(os.path.abspath(os.path.dirname(__file__)), project_name_lower, '_version.py')).read())  # get __version__

person_name = 'clach04'
person_email = None


# disable package finding, explictly list package
find_packages = False
if find_packages:
    packages = find_packages()
else:
    packages = [project_name_lower]


setup(
    name=project_name,
    version=__version__,
    url='https://github.com/clach04/' + project_name + '-py',
    author=person_name,
    author_email=person_email,
    maintainer=person_name,
    maintainer_email=person_email,
    packages=packages,
    license=license,  # NOTE http://guide.python-distribute.org/creation.html and http://docs.python.org/distutils/setupscript.html disagree on what this field is
    description=description,
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[  # See http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 4 - Beta',

        'License :: OSI Approved :: ' + license,

        'Intended Audience :: Developers',

        'Operating System :: OS Independent',
        'Operating System :: Microsoft :: Windows :: Windows NT/2000',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Unix',

        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.12',

        'Topic :: Security :: Cryptography',
        ],
    platforms='any',
    install_requires=['pycryptodome'],  # PyCrypto will also work in a pinch. TODO optional pure AES, and Jython/Java support
    zip_safe=True,
)
