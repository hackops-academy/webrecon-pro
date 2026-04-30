from setuptools import setup, find_packages

setup(
    name="webrecon-pro",
    version="1.0.0",
    description="Professional Web Penetration Testing Framework",
    author="HackOps Academy",
    url="https://github.com/hackops-academy/webrecon-pro",
    packages=find_packages(),
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.0.0",
        "httpx>=0.25.0",
        "beautifulsoup4>=4.12.0",
    ],
    entry_points={
        "console_scripts": [
            "webrecon=main:app",
        ],
    },
    python_requires=">=3.9",
)
