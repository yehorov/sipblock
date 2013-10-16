#!/usr/bin/env python

from distutils.core import setup

setup(name='sipblock',
    version='0.1',
    description='SIP Attack Blocker',
    author='Mykhaylo Yehorov',
    author_email='yehorov@gmail.com',
    url='https://github.com/yehorov/sipblock',
    license='BSD',
    scripts=['sipblock.py'],
    requires=['pylibpcap']
    )
