from setuptools import setup, find_packages

setup(
    name='remote_pcap',
    version='1.0',
    packages=find_packages(),
    long_description="Utility for easily capturing traffic remotely and displaying it.",
    author="Vladimir Muzyka",
    author_email="vladimir.muzyka@gmail.com",
    url="https://github.com/itorayn/remote_pcap",
    python_requires=">=3.8",
    entry_points={
        'console_scripts': [
            'remote_pcap = remote_pcap:run_tool_runner',
        ]
    }
)
