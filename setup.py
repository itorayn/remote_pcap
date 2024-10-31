# type: ignore
from setuptools import find_packages, setup

setup(
    name='remote_pcap',
    version='1.0.3',
    packages=find_packages(),
    long_description="Utility for easily capturing traffic remotely and displaying it.",
    author="Vladimir Muzyka",
    author_email="vladimir.muzyka@gmail.com",
    url="https://github.com/itorayn/remote_pcap",
    python_requires=">=3.8",
    install_requires=["paramiko >= 2.5.0"],
    entry_points={
        'console_scripts': [
            'remote_pcap = remote_pcap:run_tool_runner',
        ]
    }
)
