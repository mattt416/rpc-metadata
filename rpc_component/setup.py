from setuptools import setup, find_packages

setup(
    name='rpc_component',
    version='0.0.0',
    description='Tools for managing RPC components.',
    install_requires=['GitPython', 'PyYAML', 'schema'],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'component=rpc_component.cli:main',
        ],
    },
)
