import binascii
import itertools
import math
import os

from bokeh import palettes as bp
from bokeh.models import HoverTool, ColumnDataSource, CategoricalColorMapper, PrintfTickFormatter
from bokeh.plotting import figure, output_file, save, show
from pwn import *
from recordclass import recordclass
from termcolor import COLORS
from termcolor import colored

FragmentT = recordclass('Fragment', ['offset', 'frag', 'name', 'tags'])
default_tag = ['untagged']


class Fragment(FragmentT):
    def __new__(cls, *args, **kwargs):
        inst = super(Fragment, cls).__new__(cls, 0, '', '', default_tag)
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
        >>> pb = PayloadBuffer(48, dbg=True)
        >>> pb.add(16, 'ABCD', 'ret address')
        >>> pb.last_fragment_end()
        20
        >>> '10-14 ( 4): 41424344 ret address' in pb.pprint_fragments()
        True
        >>> pb.get_buffer()
        'aaaabaaacaaadaaaABCDfaaagaaahaaaiaaajaaakaaalaaa'
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
        >>> assert pb.output_viz()

    """
    def __init__(self, length=0, dbg=False):
        self.length = length
        self.debug = dbg
        self.fragments = []

    def _add(self, f):
        if self.length:
            end = f.offset + len(f.frag)
            if end > self.length:
                raise ValueError('{} out of bounds: 0x{:x}'.format(f, self.length))

        self.fragments.append(f)

    def add(self, offset, frag, name='', tags=default_tag):
        assert hasattr(tags, '__iter__')

        if isinstance(frag, PayloadBuffer):
            for f in frag.fragments:
                self._add(Fragment(offset=offset + f.offset, frag=f.frag, name=f.name, tags=f.tags))

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
                self._add(f)

        elif hasattr(frag, '__iter__'):
            for f in frag:
                self._add(Fragment(f))
        else:
            self._add(Fragment(offset=offset, frag=flat(frag), name=name, tags=tags))

    def append(self, frag, name='', tags=default_tag):
        sz = self.last_fragment_end()
        self.add(offset=sz, frag=frag, name=name, tags=tags)

    def last_fragment_end(self):
        """ Return the smallest buffer size that can accommodate all the fragments (not the total length!). """
        if not self.fragments:
            return 0

        end = max(self.fragments, key=lambda f: f.offset + len(f.frag))
        return end.offset + len(end.frag)

    def __len__(self):
        """ Return the total length of the PayloadBuffer.

        This is either the length argument to __init__ (if it was provided), or the end of the last fragment.
        """
        if self.length:
            return self.length
        else:
            return self.last_fragment_end()

    def unique_tags(self):
        return set(itertools.chain(*[f.tags for f in self.fragments]))

    def get_buffer(self):
        if self.length == 0:
            self.length = self.last_fragment_end()

        if self.debug:
            result = bytearray(cyclic(self.length))
        else:
            result = bytearray(os.urandom(self.length))

        for f in self.fragments:
            result[f.offset:(f.offset + len(f.frag))] = f.frag

        return bytes(result)

    def output_viz(self, filename='pb.html'):
        output_file(filename)
        source = ColumnDataSource(data=dict(
            offset=[f.offset for f in self.fragments],
            size=[len(f.frag) for f in self.fragments],
            name=[f.name for f in self.fragments],
            tags=[f.tags for f in self.fragments],
            ftag=[f.tags[0] if f.tags else '' for f in self.fragments],
            dump=[binascii.hexlify(f.frag[:4]) for f in self.fragments],
            yy=[0.5 for _ in range(len(self.fragments))]
        ))

        source.data['xx'] = [x[0] + x[1] / 2 for x in zip(source.data['offset'], source.data['size'])]

        x_range = [-2, self.last_fragment_end() + 2]
        y_range = [0, 2]

        factors = list(set([f.tags[0] if f.tags else '' for f in self.fragments]))
        mapper = CategoricalColorMapper(factors=factors, palette=bp.viridis(len(factors)))

        p = figure(title='Fragments', tools='hover,resize,reset,xwheel_zoom,xpan',
                   toolbar_location='above',
                   active_scroll='xwheel_zoom',
                   x_range=x_range,
                   y_range=y_range
                   )

        p.xaxis[0].formatter = PrintfTickFormatter(format="0x%x")
        p.yaxis.visible = False
        p.yaxis.axis_line_color = None
        p.yaxis.minor_tick_line_color = None
        p.yaxis.major_tick_line_color = None
        p.plot_width = 1200
        p.plot_height = 150
        p.outline_line_color = None
        p.grid.grid_line_color = None

        p.rect('xx', 'yy', 'size', 1, width_units='data', height_units='data',
               source=source, fill_alpha=0.6,
               fill_color={'field': 'ftag', 'transform': mapper},
               )

        p.select_one(HoverTool).tooltips = [
            ('offset', '@offset'),
            ('size', '@size'),
            ('dump', '@dump'),
            ('name', '@name'),
            ('tags', '@tags')
        ]

        save(p)
        return p

    def show_viz(self, filename='pb.html'):
        p = self.output_viz(filename)
        show(p)

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
        num_w = math.ceil(math.log(self.last_fragment_end(), 16))
        name_w = max(map(lambda f: len(f.name), self.fragments))
        fmt = '{:>0%dx}-{:>0%dx} ({:%dx}): {} {:%ds}' % (num_w, num_w, num_w, name_w + 1)

        tag_colors = dict(zip(
            self.unique_tags(),
            COLORS
        ))

        for f in sorted(self.fragments):
            txt = fmt.format(
                f.offset, f.offset + len(f.frag), len(f.frag),
                binascii.hexlify(f.frag[:4]),
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
        w = math.ceil(math.log(self.last_fragment_end(), 16))
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
