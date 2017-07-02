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
    * - package
      - | |commits-since|

.. |docs| image:: https://readthedocs.org/projects/payloadbf/badge/?version=latest
    :target: https://payloadbf.readthedocs.io
    :alt: Documentation Status

.. |travis| image:: https://travis-ci.org/andigena/payloadbf.svg?branch=master
    :alt: Travis-CI Build Status
    :target: https://travis-ci.org/andigena/payloadbf


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
