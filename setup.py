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
    url="https://github.com/vchinnipilli/kubestrike",
    packages=setuptools.find_packages(),
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Security Professionals'
        'Intended Audience :: Auditors'
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent'
        'Topic :: Security',
        'Topic :: Software Development :: Security Auditing Tools'
    ],
    python_requires='>=3.0',
    install_requires=requirements
)
