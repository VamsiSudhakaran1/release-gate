from setuptools import setup, find_packages

setup(
    name="release-gate",
    version="0.6.0",
    description="AI agent release decision engine — score, compare, trace, and generate evidence packs",
    author="Vamsi Sudhakaran",
    author_email="vamsi.sudhakaran@gmail.com",
    url="https://github.com/VamsiSudhakaran1/release-gate",
    packages=find_packages(),
    install_requires=[
        "pyyaml>=6.0",
        "jsonschema>=4.0",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "release-gate=release_gate.cli:main",
        ],
    },
)
