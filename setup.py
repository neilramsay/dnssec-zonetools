#!/usr/bin/env python

from setuptools import setup, find_packages
import nose2.collector

setup(name='dnssec-zonetools',
      version='0.1',
      description='DNSSEC Zone Management Tools',
      author='Neil Ramsay',
      author_email='dnssec@agentnoel.geek.nz',
      url='https://github.com/neilramsay/dnssec-zonetools',
      license='MIT',
      packages=find_packages(),
      test_suite='nose2.collector.collector'
     )
