from setuptools import setup, find_packages
from pip._internal.req import parse_requirements
import os

install_reqs = parse_requirements('requirements.txt', session='hack')

version = "0.0.1"

setup(
   name="pydatalake-gen2",
   version=version,
   packages=find_packages()
)
