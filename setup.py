import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="kubestrike",
    version="v1.0.0",
    author="vasant chinnipilli",
    author_email="vchinnipilli@gmail.com.com",
    description="A Blazing fast Security Auditing tool for Kuberentes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kubestrike",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.0',
    install_requires=requirements
)
