import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="kubestrike",
    version="v1.0",
    author="vasant chinnipilli",
    author_email="vchinnipilli@gmail.com.com",
    description="A Blazing fast Security Auditing tool for Kuberentes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vchinnipilli/kubestrike",
    packages=setuptools.find_packages(),
    python_requires='>=3.0',
    install_requires=requirements,
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security',
        'Topic :: Software Development :: Testing'
    ]
)
