try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

setup(
    name = 'ghub',
    version = '1.0',
    description = 'Command line client for github',
    py_modules = ['ghub'],
    entry_points = {
        'console_scripts' : [
            'ghub = ghub:main',
        ]},
    )
