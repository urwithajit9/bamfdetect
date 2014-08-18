#!/usr/bin/env python2

from distutils.core import setup

setup(name='bamfdetect',
      version='1.2.1',
      description='Identifies and extracts information from bots and other malware',
      author='Brian Wallace',
      author_email='bwall@ballastsecurity.net',
      url='https://github.com/bwall/bamfdetect',
      packages=['BAMF_Detect', 'BAMF_Detect.modules', 'BAMF_Detect.modules.common',],
      package_data={"BAMF_Detect.modules": ["yara/*.yara"]},
      scripts=['bamfdetect'],
      install_requires=['pefile', 'yara'],
     )