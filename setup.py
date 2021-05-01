import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="kubestriker",
    version="v1.0.0",
    author="vasant chinnipilli",
    author_email="vchinnipilli@gmail.com.com",
    description="A Blazing fast Security Auditing tool for Kuberentes",
    licnese="Apache-2.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vchinnipilli/kubestriker",
    packages=setuptools.find_packages(),
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: Apache Software License',
        'Topic :: Security',
        'Topic :: Software Development :: Testing'
    ],
    python_requires='>=3.0',
    install_requires=requirements
)
