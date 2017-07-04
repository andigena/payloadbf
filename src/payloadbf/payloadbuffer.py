import binascii
import itertools
import math
import os
from collections import namedtuple

from pwn import *
from termcolor import COLORS
from termcolor import colored

Fragment = namedtuple('Fragment', ['offset', 'frag', 'name', 'tags'])


class PayloadBuffer:
    r""" Simple class that makes construction of exploit payloads a little more convenient.

    It's just a dictionary of offsets into the buffer and the corresponding fragments of the payload.
    The debug parameter controls whether the buffer is pre-filled with random bytes or a cyclic pattern.

    Arguments:
        length(int): The length of the buffer.
        dbg(bool): If True, gaps are filled with random data, otherwise with a cyclic pattern.

    Examples:
        >>> pb = PayloadBuffer(32, dbg=True)
        >>> pb.add(16, 'ABCD', 'ret address')
        >>> pb.size()
        20
        >>> '10-14 ( 4): 41424344 ret address' in pb.pprint_fragments()
        True
        >>> pb.get_buffer()
        'aaaabaaacaaadaaaABCDfaaagaaahaaa'
        >>> pb.add(28, 'EFGH', 'pivot', ['chain A'])
        >>> pb.pprint_gaps()
        ' 0-10 (10)\n14-1c ( 8)'

    """
    def __init__(self, length=0, dbg=False):
        self.length = length
        self.debug = dbg
        self.fragments = []

    def add(self, offset, frag, name='', tags=[]):
        self.fragments.append(Fragment(offset=offset, frag=flat(frag), name=name, tags=tags))

    def append(self, frag, name='', tags=[]):
        sz = self.size()
        self.fragments.append(Fragment(offset=sz, frag=flat(frag), name=name, tags=tags))

    """ Returns the smallest buffer size that can accommodate all the fragments (not the total length!). """
    def size(self):
        if not self.fragments:
            return 0

        end = max(self.fragments, key=lambda f: f.offset + len(f.frag))
        return end.offset + len(end.frag)

    def get_buffer(self):
        if self.length == 0:
            self.length = self.size()

        if self.debug:
            result = bytearray(cyclic(self.length))
        else:
            result = bytearray(os.urandom(self.length))

        for f in self.fragments:
            result[f.offset:(f.offset + len(f.frag))] = f.frag

        return bytes(result)

    def pprint_fragments(self, colorized=True):
        r""" pprint_fragments(self, colorized=True):

        Pretty-prints the fragments in the PayloadBuffer.

        Arguments:
            colorized(bool): Controls if the returned string is colorized.

        Returns:
            A string containing an overview of the fragments.
        """
        res = []
        w = math.ceil(math.log(self.size(), 16))
        fmt = '{:>0%dx}-{:>0%dx} ({:%dx}): {} {} ({})' % (w, w, w)

        tag_colors = dict(zip(
            set(itertools.chain(*[f.tags for f in self.fragments])),
            COLORS
        ))

        for f in sorted(self.fragments):
            txt = fmt.format(
                f.offset, f.offset + len(f.frag), len(f.frag),
                binascii.hexlify(f.frag[:4]).decode('latin-1'),
                f.name, f.tags
            )
            if colorized:
                txt = colored(txt, tag_colors[f.tags[0]] if f.tags else 'white')
            res.append(txt)

        return '\n'.join(res)

    def pprint_gaps(self):
        res = []
        w = math.ceil(math.log(self.size(), 16))
        fmt_collision = 'Collision at {:>0%dx}-{:>0%dx} ({:%dx}) overlaps {:>0%dx}-{:>0%dx} for {:%dx} bytes' % (
            w, w, w, w, w, w
        )
        fmt_gap = '{:>%dx}-{:>%dx} ({:%dx})' % (w, w, w)

        frags = sorted(self.fragments)
        first = frags[0]

        if first.offset != 0:
            res.append(fmt_gap.format(0, first.offset, first.offset))

        for i in range(len(frags) - 1):
            for j in range(i + 1, len(frags)):
                if frags[i].offset + len(frags[i].frag) > frags[j].offset:
                    res.append(fmt_collision.format(
                        frags[i].offset, frags[i].offset + len(frags[i].frag), len(frags[i].frag),
                        frags[j].offset, frags[j].offset + len(frags[j].frag), len(frags[j].frag),
                    ))
                else:
                    break

            gap_len = frags[i + 1].offset - (frags[i].offset + len(frags[i].frag))
            if gap_len > 0:
                res.append(fmt_gap.format(frags[i].offset + len(frags[i].frag), frags[i + 1].offset, gap_len))

        return '\n'.join(res)
