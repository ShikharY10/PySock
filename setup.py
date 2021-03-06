from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

VERSION = '0.0.3'
DESCRIPTION = 'Pyckage for creating high level multi-client server with E2E encryption.'
LONG_DESCRIPTION = 'A package that allows to code a server which can handle multiple connections at a time with E2E encryption. It also allows two client to talk together with the help of server'

# Setting up
setup(
    name="PySock",
    version=VERSION,
    author="Shikhar Yadav",
    author_email="<yshikharfzd10@gmail.com>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    url = "https://github.com/ShikharY10/PySock",
    project_urls={
    'Github': 'https://github.com/ShikharY10/PySock',
    'Shikhar Yadav': 'https://github.com/ShikharY10',
    },
    packages=find_packages(),
    install_requires=['PyYAML','cryptography'],
    keywords=['socket', 'tcp', 'stream', 'encrypted', 'E2E', 'multi-client-server'],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: Microsoft :: Windows",
    ]
)