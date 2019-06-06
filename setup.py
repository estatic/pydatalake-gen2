from setuptools import setup, find_packages
from pip._internal.req import parse_requirements

install_reqs = parse_requirements("requirements.txt", session="hack")

version = "0.0.4"

setup(
    name="pydatalake-gen2",
    description="REST API Client to Azure Data Lake Gen2",
    author="Ivan Grunev",
    author_email="ivan.grunev@gmail.com",
    include_package_data=True,
    version=version,
    url="https://github.com/estatic/pydatalake-gen2",
    packages=find_packages(),
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
