from os import path
from setuptools import setup, find_packages

with open(path.join(path.abspath(path.dirname(__file__)), "README.rst"), encoding="utf-8") as handle:
    readme = handle.read()

setup(
    name="spectral-aead",
    version="0.0.5",
    description="An algorithm for authenticated encryption with associated data using Speck and HMAC-SHA256.",
    long_description=readme,
    url="https://github.com/kpdemetriou/spectral-aead",
    author="Phil Demetriou",
    author_email="inbox@philonas.net",
    license="BSD",
    packages=find_packages(exclude=["tests"]),
    setup_requires=["cffi>=1.4.0"],
    cffi_modules=["build.py:spectral_ffi"],
    install_requires=["cffi>=1.4.0"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: C",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
    ],
)
