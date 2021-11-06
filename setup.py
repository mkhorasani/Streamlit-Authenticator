import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="streamlit-authenticator",
    version="0.0.1",
    author="Mohammad Khorasani",
    author_email="khorasani.mohammad@gmail.com",
    description="A secure authenticaton module to validate users' credentials in your Streamlit application.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mkhorasani/Streamlit-Authenticator",
    packages=setuptools.find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache License",
        "Operating System :: OS Independent",
    ],
    keywords=['Python', 'Streamlit', 'Authentication', 'Components'],
    python_requires=">=3.6",
    install_requires=[
        "streamlit >= 0.86",
        "extra-streamlit-components >= 0.1.52"
    ],
)
