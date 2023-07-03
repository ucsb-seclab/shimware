#!/usr/bin/env python
"""
    This is our Python package for Shimware
"""
import os
from distutils.core import setup


def get_packages(rel_dir):
    packages = [rel_dir]
    for x in os.walk(rel_dir):
        # break into parts
        base = list(os.path.split(x[0]))
        if base[0] == "":
            del base[0]

        for mod_name in x[1]:
            packages.append(".".join(base + [mod_name]))

    return packages


setup(name='shimware',
      version='0.1',
      description='This is the Python library for shimware',
      author='Eric Gustafson',
      author_email='edg@cs.ucsb.edu',
      url='https://seclab.cs.ucsb.edu',
      packages=get_packages('shimware'),
      install_requires=["pyelftools", "pyaml"]
      )
