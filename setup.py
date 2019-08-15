from setuptools import setup, find_packages
from pip._internal.req import parse_requirements

install_reqs = parse_requirements("requirements.txt", session="hack")

with open("README.md") as f:
    README = f.read()

version = "0.0.5"

setup(
    name="pydatalake-gen2",
    description="REST API Client to Azure Data Lake Gen2",
    author="Ivan Grunev",
    author_email="ivan.grunev@gmail.com",
    include_package_data=True,
    long_description=README,
    python_requires=">=3.4",
    version=version,
    url="https://github.com/estatic/pydatalake-gen2",
    packages=find_packages(),
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 — Alpha",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
