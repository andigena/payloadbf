import binascii
import functools
import itertools
import math
import os

from bokeh import palettes as bp
from bokeh.models import HoverTool, ColumnDataSource, CategoricalColorMapper, Legend, PrintfTickFormatter, \
    FixedTicker, Panel, Tabs
from bokeh.plotting import figure, output_file, output_notebook, save, show
from pwn import *
from recordclass import recordclass
from termcolor import COLORS
from termcolor import colored

FragmentT = recordclass('Fragment', ['offset', 'frag', 'name', 'tags'])
default_tag = ['untagged']


@functools.total_ordering
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

        inst.frag = flat(inst.frag)
        return inst

    def __len__(self):
        return len(self.frag)

    def __lt__(self, other):
        return self.offset < other.offset

    def __eq__(self, other):
        return self.offset == other.offset


class PayloadBuffer:
    r""" Simple class that makes construction of exploit payloads a little more convenient.

    It's a dictionary of offsets into the buffer and the corresponding fragments of the payload. Gaps between the
    fragments are filled with `filler`, which defaults to cyclic. Fragment buffers are automatically flattened via
    `flat from pwntools
    <http://docs.pwntools.com/en/stable/util/packing.html#pwnlib.util.packing.flat>`_.

    Arguments:
        length(int): The length of the buffer.
        filler(callable): a callable with a single length parameter. Its return value is used to fill gaps. Defaults
            to cyclic.

    Examples:
        >>> pb = PayloadBuffer(48)
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
        >>> context.arch = 'i386'
        >>> another.append({
        ...     0: '1234',
        ...     4: {
        ...         'frag': 0x35363738,
        ...         'name': 'filler2',
        ...         'tags': ['chain C']
        ...     },
        ...     8: ['9abc', 'saved retaddr', ['chain C', 'retaddr']]
        ... })
        >>> pb.append(another)
        >>> pb.get_buffer()[36:40] == '1234'
        True
        >>> pb.get_buffer()[40:44] == '8765'
        True
        >>> assert pb.output_viz(1200, 400)
    """
    def __init__(self, length=0, filler=cyclic):
        self.length = length
        self.filler = filler
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
            self._add(Fragment(offset=offset, frag=frag, name=name, tags=tags))

    def append(self, frag, name='', tags=default_tag):
        sz = self.last_fragment_end()
        self.add(offset=sz, frag=frag, name=name, tags=tags)

    def last_fragment_end(self):
        """ last_fragment_end(self) -> int

        Return the smallest buffer size that can accommodate all the fragments (not the total length!).
        """
        if not self.fragments:
            return 0

        end = max(self.fragments, key=lambda f: f.offset + len(f.frag))
        return end.offset + len(end.frag)

    def __len__(self):
        """ __len__(self) -> int

        Return the total length of the PayloadBuffer. This is either the length argument to __init__ (if it was
        provided), or the end of the last fragment.
        """
        if self.length:
            return self.length
        else:
            return self.last_fragment_end()

    @staticmethod
    def _key_to_offsets(key):
        if isinstance(key, slice):
            start = key.start
            stop = key.stop
        else:
            start = key
            stop = key + 1

        return start, stop

    def __getitem__(self, key):
        r""" __getitem__(self, key) -> list

        Get a list of Fragments overlapping the given offset or an empty list if there are no overlaps. It works
        similarly to how Python handles list indices (inclusive on the lower, exclusive on the upper end). Due to the
        nature of the lookup, neither negative indices nor slice steps make no sense.

        Arguments:
            key(int, slice): Offset

        Returns:
            A list containing the Fragments overlapped by key.

        Examples:
            >>> pb = PayloadBuffer(256)
            >>> pb.add(16, '1111')
            >>> pb.add(20, '2222')
            >>> pb[16]
            [Fragment(offset=16, frag='1111', name='', tags=['untagged'])]
            >>> pb[16:20]
            [Fragment(offset=16, frag='1111', name='', tags=['untagged'])]
            >>> pb[16:21]
            [Fragment(offset=16, frag='1111', name='', tags=['untagged']), Fragment(offset=20, frag='2222', name='', tags=['untagged'])]
        """
        results = []
        fragments = sorted(self.fragments)
        start, stop = self._key_to_offsets(key)
        for f in fragments:
            fend = f.offset + len(f)
            if fend <= start:
                # not there yet
                continue
            if f.offset >= stop:
                # no possible overlaps left
                break

            results.append(f)   # everything else must overlap with the interval

        return results

    def unique_tags(self):
        return set(itertools.chain(*[f.tags for f in self.fragments]))

    def unique_main_tags(self):
        return set((f.tags[0] for f in self.fragments))

    def fragments_groupby_mtag(self, fragments=None):
        r""" fragments_groupby_mtag(self) -> iterator

        Group fragments by their main tag.

        Returns:
            an iterator of (main_tag, group) pairs.
        """
        def key(fr):
            return fr.tags[0]

        if fragments is None:
            fragments = self.fragments
        sorted_fragments = sorted(fragments, key=key)
        return itertools.groupby(sorted_fragments, key=key)

    def get_buffer(self):
        if self.length == 0:
            self.length = self.last_fragment_end()

        result = bytearray(self.filler(self.length))
        for f in self.fragments:
            result[f.offset:(f.offset + len(f.frag))] = f.frag

        return bytes(result)

    @staticmethod
    def _add_legend(p, renderers, loc=(10, -30)):
        legend = Legend(items=renderers, location=loc)
        legend.click_policy = "mute"
        p.add_layout(legend, 'right')

    def _gen_1d_chart(self, width, height):
        x_range = [-2, self.last_fragment_end() + 2]
        y_range = [0, 2]

        factors = tuple(self.unique_main_tags())
        mapper = CategoricalColorMapper(factors=factors, palette=bp.viridis(len(factors)))

        p = figure(title='Fragments', tools='hover,resize,reset,xwheel_zoom,xpan',
                   toolbar_location='above', active_scroll='xwheel_zoom',
                   x_range=x_range, y_range=y_range,
                   plot_width=width, plot_height=height // 2  # TODO calculate this sanely
                   # responsive=True
                   )

        p.xaxis[0].formatter = PrintfTickFormatter(format="0x%x")
        p.xaxis.bounds = (0, len(self))
        p.yaxis.visible = False
        p.yaxis.axis_line_color = None
        p.yaxis.minor_tick_line_color = None
        p.yaxis.major_tick_line_color = None

        p.outline_line_color = None
        p.grid.grid_line_color = None

        renderers = []
        for mtag, gr in self.fragments_groupby_mtag():
            gr = list(gr)
            cds = ColumnDataSource(data=dict(
                offset=[f.offset for f in gr],
                size=[len(f.frag) for f in gr],
                name=[f.name for f in gr],
                tags=[f.tags for f in gr],
                ftag=[mtag for _ in range(len(gr))],
                dump=[binascii.hexlify(f.frag[:4]) for f in gr],
                xx=[f.offset + (len(f.frag)) / 2 for f in gr],
                yy=[0.5 for _ in range(len(gr))]
            ))
            renderer = p.rect('xx', 'yy', 'size', 1, width_units='data', height_units='data',
                              source=cds, fill_alpha=0.6,
                              fill_color={'field': 'ftag', 'transform': mapper},
                              hover_alpha=0.2,
                              muted_alpha=0.2
                              )
            renderers.append((mtag, [renderer]))

        self._add_legend(p, renderers)
        p.select_one(HoverTool).tooltips = [
            ('offset', '@offset'),
            ('size', '@size'),
            ('dump', '@dump'),
            ('name', '@name'),
            ('tags', '@tags')
        ]

        return p

    @staticmethod
    def _gen_coords(fragments, row_width):
        r""" Generate coordinates for the Patches glyph used to draw the 2D plot, split fragments on row boundaries."""
        def get_patch(s, e):
            r""" Get the coordinates for a rectangular patch starting at s and ending at e."""
            s_x = s % row_width
            e_x = e % row_width if e % row_width else row_width
            xt = [s_x, s_x, e_x, e_x]
            yt = [align(row_width, s + 1), align_down(row_width, s),
                  align_down(row_width, s), align(row_width, s + 1)]
            return xt, yt

        xx = []
        yy = []
        nan = float('nan')
        for f in fragments:
            end = f.offset + len(f.frag)
            start = f.offset
            overlaps_boundary = (align(row_width, start + 1) != align(row_width, end + 1)) and start != end
            if overlaps_boundary:
                # split into as many patches as needed
                x_coords = []
                y_coords = []
                while start < end:
                    rem_start = align(row_width, start + 1)
                    if rem_start > end:
                        rem_start = end
                    xt, yt = get_patch(start, rem_start)
                    x_coords.extend(xt + [nan])
                    y_coords.extend(yt + [nan])
                    start = rem_start

            else:
                x_coords, y_coords = get_patch(start, end)

            xx.append(x_coords)
            yy.append(y_coords)

        return xx, yy

    def _gen_2d_chart(self, width, height, row_width=64, ticks_per_row=4):
        r""" _gen_2d_chart2(self, width, height, row_width=64, ticks_per_row=4) -> LayoutDOM

        Generate a 2D chart of the fragments. Fragments overlapping row boundaries are drawn using Patches with missing
        points, so that hover/highlighting works as expected.

        Arguments:
            width(int):  Plot width
            height(int): Plot height
            row_width(int): Length of the x axis.
            ticks_per_row(int): Tick count of the x axis.

        Returns:
            A string containing an overview of the fragments.
        """
        fragments = sorted(self.fragments)
        last_end = align(row_width, self.last_fragment_end() + 1)
        x_range = (0, row_width + 1)
        y_range = (last_end, 0)

        factors = tuple(self.unique_main_tags())
        mapper = CategoricalColorMapper(factors=factors, palette=bp.viridis(len(factors)))

        p = figure(title='Fragments', tools='hover,resize,reset,wheel_zoom,pan',
                   toolbar_location='below', active_scroll='wheel_zoom',
                   x_range=x_range, y_range=y_range,
                   x_axis_location='above',
                   plot_width=width, plot_height=height
                   # responsive=True
                   )

        p.xaxis[0].formatter = PrintfTickFormatter(format="0x%x")
        p.yaxis[0].formatter = PrintfTickFormatter(format="0x%x")
        p.xaxis[0].ticker = FixedTicker(ticks=range(0, row_width + 1, row_width // ticks_per_row))
        p.yaxis[0].ticker = FixedTicker(ticks=range(0, last_end + 1, row_width))
        p.axis.major_label_standoff = 0
        p.xaxis.bounds = (0, row_width)
        p.yaxis.major_tick_line_color = None
        p.yaxis.minor_tick_line_color = None
        p.outline_line_color = None
        p.grid.grid_line_color = None

        renderers = []
        for mtag, gr in self.fragments_groupby_mtag(fragments):
            gr = list(gr)
            xx, yy = self._gen_coords(gr, row_width)
            cds = ColumnDataSource(data=dict(
                offset=[f.offset for f in gr],
                size=[len(f.frag) for f in gr],
                name=[f.name for f in gr],
                tags=[f.tags for f in gr],
                ftag=[mtag for _ in range(len(gr))],
                dump=[binascii.hexlify(f.frag[:4]) for f in gr],
                xx=xx,
                yy=yy,
            ))
            renderer = p.patches('xx', 'yy',
                                 source=cds, fill_alpha=0.6,
                                 fill_color={'field': 'ftag', 'transform': mapper},
                                 hover_alpha=0.2,
                                 muted_alpha=0.2
                                 )
            renderers.append((mtag, [renderer]))

        self._add_legend(p, renderers)

        p.select_one(HoverTool).tooltips = [
            ('offset', '@offset'),
            ('size', '@size'),
            ('dump', '@dump'),
            ('name', '@name'),
            ('tags', '@tags'),
        ]

        return p

    def output_viz(self, width, height):
        p2d = self._gen_2d_chart(width, height)
        tab2 = Panel(child=p2d, title="2D")
        p1d = self._gen_1d_chart(width, height)
        tab1 = Panel(child=p1d, title="1D")
        tabs = Tabs(tabs=[tab2, tab1])
        return tabs

    def show_viz(self, width=1200, height=400, filename='pb.html'):
        output_file(filename)
        p = self.output_viz(width, height)
        save(p)
        show(p)

    def show_viz_notebook(self, width=1200, height=400):
        output_notebook()
        p = self.output_viz(width, height)
        show(p)

    def pprint_fragments(self, colorized=True):
        r""" pprint_fragments(self, colorized=True) -> str

        Pretty-print the fragments in the PayloadBuffer.

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
