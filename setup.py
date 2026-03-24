from setuptools import setup, find_packages

setup(
    name="release-gate",
    version="0.3.0",
    description="Governance enforcement for AI agents",
    author="Vamsi Sudhakaran",
    author_email="vamsi.sudhakaran@gmail.com",
    url="https://github.com/VamsiSudhakaran1/release-gate",
    packages=find_packages(),
    install_requires=[
        "pyyaml>=6.0",
        "jsonschema>=4.0",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "release-gate=release_gate.cli:main",
        ],
    },
)