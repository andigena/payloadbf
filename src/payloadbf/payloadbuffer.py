import binascii
import itertools
import math
import operator
import os

from pwn import *


class PayloadBuffer:
    r""" Simple class that makes construction of exploit payloads a little more convenient.

    It's just a dictionary of offsets into the buffer and the corresponding fragments of the payload.
    The debug parameter controls whether the buffer is pre-filled with random bytes or a cyclic pattern.

    Arguments:
        length(int): The length of the buffer.
        debug(bool): If True, gaps are filled with random data, otherwise with a cyclic pattern.

    Examples:
        >>> pb = PayloadBuffer(32, debug=True)
        >>> pb.add(16, 'ABCD', 'ret address')
        >>> pb.pprint_fragments()
        '\t10-14 ( 4): 41424344 (ret address)'
        >>> pb.get_buffer()
        'aaaabaaacaaadaaaABCDfaaagaaahaaa'

        >>> pb = PayloadBuffer(debug=True)

    """
    def __init__(self, length=0, debug=False):
        self.length = length
        self.debug = debug
        self.fragments = {}

    def add(self, offset, frag, tag=''):
        self.fragments[offset] = {
            'frag': flat(frag),
            'tag': tag
        }

    def append(self, frag, tag=''):
        size = self.size()
        self.fragments[size] = {
            'frag': flat(frag),
            'tag': tag
        }

    """ Returns the smallest buffer size that can accommodate all the fragments. """
    def size(self):
        tupled = zip(self.fragments.keys(), map(lambda x: len(x['frag']), self.fragments.values()))
        return max(itertools.starmap(operator.add, tupled))

    def get_buffer(self):
        if self.length == 0:
            self.length = self.size()

        if self.debug:
            result = bytearray(cyclic(self.length))
        else:
            result = bytearray(os.urandom(self.length))

        for offset, frag in self.fragments.items():
            result[offset:(offset + len(frag['frag']))] = frag['frag']

        return bytes(result)

    def pprint_fragments(self):
        res = []
        w = math.ceil(math.log(self.size(), 16))
        fmt = '\t{:>0%dx}-{:>0%dx} ({:%dx}): {} ({})' % (w, w, w)

        for off, f in sorted(self.fragments.items()):
            res.append(fmt.format(off, off + len(f['frag']), len(f['frag']), binascii.hexlify(f['frag'][:4]).decode('latin-1'), f['tag']))

        return '\n'.join(res)

    def pprint_gaps(self):
        res = []
        w = math.ceil(math.log(self.size(), 16))
        fmt_collision = '\tCollision at {:>0%dx}-{:>0%dx} ({:%dx}) overlaps {:>0%dx}-{:>0%dx} for {:%dx} bytes' % (
            w, w, w, w, w, w
        )
        fmt_gap = '\t{:>%dx}-{:>%dx} ({:%dx})' % (w, w, w)

        frags = sorted(self.fragments.items())
        for i in range(len(frags)-1):
            for j in range(i+1, len(frags)):
                if frags[i][0] + len(frags[i][1]['frag']) > frags[j][0]:
                    res.append(fmt_collision.format(
                        frags[i][0], frags[i][0] + len(frags[i][1]['frag']), len(frags[i][1]['frag']),
                        frags[j][0], frags[j][0] + len(frags[j][1]['frag']), len(frags[j][1]['frag']),
                    ))
                else:
                    break

            gap_len = frags[i+1][0] - (frags[i][0] + len(frags[i][1]['frag']))
            if gap_len > 0:
                res.append(fmt_gap.format(frags[i][0] + len(frags[i][1]['frag']), frags[i+1][0], gap_len))

        return '\n'.join(res)
