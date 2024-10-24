from setuptools import setup, find_packages

setup(
    name='packet-analyzer',
    version='1.0.0',
    author='Yusuf Enes',
    author_email='yusufenes@duck.com',
    description='Ağ Trafiği Paket Analiz Aracı',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'psutil',
        'scapy',
        'requests',
        'matplotlib',
        'tkinter'
    ],
    entry_points={
        'console_scripts': [
            'packet-analyzer=packet_analyzer.main:main',
        ],
    },
)
