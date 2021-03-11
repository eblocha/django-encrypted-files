import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "django_encrypted_files",
    version = "0.0.8",
    author = "Elliott Blocha",
    description = "Encrypt files uploaded to a Django application.",
    license = "MIT",
    keywords = "cryptography, big, large, encryption",
    packages=['encrypted_files'],
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
    ],
    install_requires=["cryptography"],
     python_requires='>=3.6, <4',
)