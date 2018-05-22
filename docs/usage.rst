=====
Usage
=====

This library provides functionality similar to the fit_ function from `pwntools` with visualization support. Its main goal is to make creating complicated exploit payloads easier.

The main inspiration was the following scenario: let's assume that we're writing an exploit for a plain stack based buffer overflow and we need to support multiple versions of the program affected using the same payload. There's a module without ASLR support. All the modules are recompiled between versions, so:

- the saved return address we overwrite might be at different offsets
- the module without ASLR might have ROP gadgets at different addresses or different gadgets at the same offsets

Creating such a payload gets gets messy quickly, as we need to juggle dispatchers, stack pivots and ROP chains.

.. code-block:: python


:doc:`PayloadBuffer <reference/payloadbuffer>` is the main class to interact with.

.. _fit: http://docs.pwntools.com/en/stable/util/packing.html#pwnlib.util.packing.fit

