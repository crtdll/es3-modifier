from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as fh:
  long_description = fh.read()

setup(
  name='es3-modifier',
  version='0.1.0',
  author='crtdll',
  description='A package to decrypt, edit and encrypt EasySave files used in Unity games',
  long_description=long_description,
  long_description_content_type='text/markdown',
  url='https://github.com/crtdll/es3-modifier',
  packages=find_packages(),
  include_package_data=True,
  install_requires=[
    'pycryptodome',
  ],
  entry_points={
    'console_scripts': [
      'es3-modifier=es3_modifier.main:main',
    ],
  },
)
