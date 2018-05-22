========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - | |travis|
    * - commits since release
      - | |commits-since|

.. |docs| image:: https://readthedocs.org/projects/payloadbf/badge/?version=latest
    :target: https://payloadbf.readthedocs.io
    :alt: Documentation Status

.. |travis| image:: https://travis-ci.org/andigena/payloadbf.svg?branch=master
    :alt: Travis-CI Build Status
    :target: https://travis-ci.org/andigena/payloadbf

.. |commits-since| image:: https://img.shields.io/github/commits-since/andigena/payloadbf/v0.2.0.svg
    :alt: Commits since latest release
    :target: https://github.com/andigena/payloadbf/compare/v0.2.0...master


.. end-badges

A somewhat more enjoyable payload generation for exploit developers.

* Free software: MIT license


Documentation
=============

https://payloadbf.readthedocs.io/

Development
===========

To run the all tests run::

    tox

Note, to combine the coverage data from all the tox environments run:

.. list-table::
    :widths: 10 90
    :stub-columns: 1

    - - Windows
      - ::

            set PYTEST_ADDOPTS=--cov-append
            tox

    - - Other
      - ::

            PYTEST_ADDOPTS=--cov-append tox
