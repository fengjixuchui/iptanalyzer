import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyiptanalyzertool-ohjeongwook",
    version="0.0.1",
    author="Matt Oh",
    author_email="jeongoh@darungrim.com",
    description="WinDbg Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ohjeongwook/iptanalyzer",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=2.7',
)
