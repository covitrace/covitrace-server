#!/usr/bin/env python3

from setuptools import setup

setup(
    name = 'covitrace',
    version = '0.1.0',
    description = 'CoviTrace API server',
    #packages = ['covitrace'],
    #scripts = ['covitrace_api'],
    install_requires = [
        'Flask == 1.1.1',
        'psycopg2-binary == 2.8.4',
        'gunicorn == 20.0.4',
    ],
)
