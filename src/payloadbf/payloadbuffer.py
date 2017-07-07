import binascii
import itertools
import math
import os
from collections import namedtuple

from pwn import *
from recordclass import recordclass
from termcolor import COLORS
from termcolor import colored

FragmentT = recordclass('Fragment', ['offset', 'frag', 'name', 'tags'])


class Fragment(FragmentT):
    def __new__(cls, *args, **kwargs):
        inst = super(Fragment, cls).__new__(cls, 0, '', '', [])
        if len(args) == 1 and hasattr(args[0], '__iter__'):
            for idx, prop in enumerate(args[0]):
                inst[idx] = prop
        else:
            for idx, prop in enumerate(args):
                inst[idx] = prop
            for k, prop in kwargs.items():
                inst.__setattr__(k, prop)

        return inst


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
        >>> another = PayloadBuffer()
        >>> another.add(0, [(0, 'as'), (2, 'df')])
        >>> another.append({
        ...     0: '1234',
        ...     4: {
        ...         'frag': '5678',
        ...         'name': 'filler2',
        ...         'tags': ['chain C']
        ...     },
        ...     8: ['9abc', 'saved retaddr', ['chain C', 'retaddr']]
        ... })
        >>> pb.append(another)
        >>> pb.get_buffer()[36:40] == '1234'
        True
    """
    def __init__(self, length=0, dbg=False):
        self.length = length
        self.debug = dbg
        self.fragments = []

    def add(self, offset, frag, name='', tags=[]):
        assert hasattr(tags, '__iter__')

        if isinstance(frag, PayloadBuffer):
            for f in frag.fragments:
                self.fragments.append(Fragment(offset=offset + f.offset, frag=f.frag, name=f.name, tags=f.tags))

        elif isinstance(frag, dict):
            # a dictionary
            for off, props in frag.items():
                if isinstance(props, str):
                    # only a fragment buffer
                    f = Fragment(offset=offset + off, frag=props)
                elif isinstance(props, dict):
                    f = Fragment(offset + off, **props)
                elif hasattr(props, '__iter__'):
                    f = Fragment([offset + off] + [p for p in props])
                else:
                    raise 'Unsupported invocation of add'
                self.fragments.append(f)

        elif hasattr(frag, '__iter__'):
            for f in frag:
                self.fragments.append(Fragment(f))
        else:
            self.fragments.append(Fragment(offset=offset, frag=flat(frag), name=name, tags=tags))

    def append(self, frag, name='', tags=[]):
        sz = self.size()
        self.add(offset=sz, frag=frag, name=name, tags=tags)

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
        if not self.fragments:
            return ''

        res = []
        num_w = math.ceil(math.log(self.size(), 16))
        name_w = max(map(lambda f: len(f.name), self.fragments))
        fmt = '{:>0%dx}-{:>0%dx} ({:%dx}): {} {:%ds}' % (num_w, num_w, num_w, name_w + 1)

        tag_colors = dict(zip(
            set(itertools.chain(*[f.tags for f in self.fragments])),
            COLORS
        ))

        for f in sorted(self.fragments):
            txt = fmt.format(
                f.offset, f.offset + len(f.frag), len(f.frag),
                binascii.hexlify(f.frag[:4]).decode('latin-1'),
                f.name
            )
            if colorized:
                txt = colored(txt, tag_colors[f.tags[0]] if f.tags else 'white')
                tags_str = ' (' + ', '.join([colored(t, tag_colors[t]) for t in f.tags]) + ')'
            else:
                tags_str = ' (' + ', '.join(f.tags) + ')'

            txt += tags_str
            res.append(txt)

        return '\n'.join(res)

    def pprint_gaps(self):
        if not self.fragments:
            return ''

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
