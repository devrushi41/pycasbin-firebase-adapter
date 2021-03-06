from setuptools import setup, find_packages
from os import path

desc_file = "README.md"

with open(desc_file, "r") as fh:
    long_description = fh.read()

here = path.abspath(path.dirname(__file__))
# get the dependencies and installs
with open(path.join(here, "requirements.txt"), encoding="utf-8") as f:
    all_reqs = f.read().split("\n")

install_requires = [x.strip() for x in all_reqs if "git+" not in x]

setup(
    version="0.0.1",
    name="pycasbin_firebase_adapter",
    author="DevRushi",
    author_email="devrushi41@gmail.com",
    description="Fibase Adapter for PyCasbin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/devrushi41/pycasbin-firebase-adapter",
    keywords=[
        "casbin",
        "firebase",
        "casbin-adapter",
        "rbac",
        "access control",
        "abac",
        "acl",
        "permission",
    ],
    packages=find_packages(),
    install_requires=install_requires,
    python_requires=">=3.3",
    license="Apache 2.0",
    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    data_files=[desc_file],
)
