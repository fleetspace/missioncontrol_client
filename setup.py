#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from setuptools import find_packages, setup


install_requires = [
    "requests",
]


def readme():
    try:
        return open('README.md', encoding='utf-8').read()
    except TypeError:
        return open('README.md').read()


setup(
    name='missioncontrol-client',
    packages=find_packages(),
    version='0.0.3',
    description='python client for the missioncontrol api',
    long_description=readme(),
    author='Fleet Space Technologies',
    license='Apache License Version 2.0',
    url='https://github.com/fleetspace/missioncontrol_client',
    install_requires=install_requires,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Development Status :: 1 - Planning',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent'
    ]
)
