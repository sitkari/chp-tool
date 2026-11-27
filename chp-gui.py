#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""chp-gui.py — GUI wrapper around chp.py (device firmware .chp).

Run from source:        python chp-gui.py [file.chp]
Build exe:              build-exe.bat  (or see README.md)
"""

from __future__ import annotations

import hashlib
import io
import os
import sys
import traceback

if sys.stdout is None:
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import chp

APP_TITLE = 'CHP firmware — unpack and build'
MONO = ('Consolas', 10)
CHP_TYPES = [('Firmware container', '*.chp'), ('All files', '*.*')]


def human_name(b: bytes) -> str:
    return b.decode('cp1251', 'replace')


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry('1000x760')
        self.minsize(860, 640)
        try:
            ttk.Style(self).theme_use('vista')
        except tk.TclError:
            pass

        self.base: chp.Container | None = None
        self.base_path = ''
        self.edits: list[tuple[int, int, str]] = []

        self._vars()
        self._layout()
        self._bind_keys()

    # ------------------------------------------------------------------ UI --
    def _vars(self) -> None:
        self.src_var = tk.StringVar()
        self.bin_var = tk.StringVar()
        self.pack_out_var = tk.StringVar()
        self.pack_sub_var = tk.StringVar()
        self.pack_ver_var = tk.StringVar()
        self.pack_name_var = tk.StringVar()
        self.pack_fixck_var = tk.BooleanVar(value=True)

        self.set_out_var = tk.StringVar()
        self.set_sub_var = tk.StringVar()
        self.set_ver_var = tk.StringVar()
        self.set_name_var = tk.StringVar()
        self.set_fixck_var = tk.BooleanVar(value=True)

        self.edit_addr_var = tk.StringVar()
        self.edit_val_var = tk.StringVar()
        self.edit_kind_var = tk.StringVar(value='word')
        self.status_var = tk.StringVar(value='no file selected')

    def _layout(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # --- source file --------------------------------------------------
        top = ttk.LabelFrame(self, text=' Source .chp container ')
        top.grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 4))
        top.columnconfigure(1, weight=1)
        ttk.Entry(top, textvariable=self.src_var).grid(
            row=0, column=0, columnspan=2, sticky='ew', padx=8, pady=6)
        ttk.Button(top, text='Browse…', command=self.pick_src).grid(
            row=1, column=0, sticky='w', padx=8, pady=(0, 8))
        ttk.Button(top, text='Load', command=self.reload).grid(
            row=1, column=1, sticky='w', padx=8, pady=(0, 8))

        # --- tabs ---------------------------------------------------------
        nb = ttk.Notebook(self)
        nb.grid(row=1, column=0, sticky='nsew', padx=10)
        self.tab_info = ttk.Frame(nb, padding=8)
        self.tab_pack = ttk.Frame(nb, padding=8)
        self.tab_edit = ttk.Frame(nb, padding=8)
        nb.add(self.tab_info, text='  Info  ')
        nb.add(self.tab_pack, text='  Build from .bin  ')
        nb.add(self.tab_edit, text='  Byte edits  ')
        self.nb = nb
        env_tab = os.environ.get('CHP_TAB', '').strip()
        if env_tab.isdigit():
            try:
                nb.select(int(env_tab))
            except tk.TclError:
                pass

        self._build_info_tab()
        self._build_pack_tab()
        self._build_edit_tab()

        # --- log ----------------------------------------------------------
        logf = ttk.LabelFrame(self, text=' Log ')
        logf.grid(row=2, column=0, sticky='ew', padx=10, pady=6)
        logf.columnconfigure(0, weight=1)
        self.log_text = tk.Text(logf, height=11, font=MONO, wrap='none',
                                state='disabled', background='#101418',
                                foreground='#d8dee9', insertbackground='#d8dee9')
        self.log_text.grid(row=0, column=0, sticky='ew', padx=(8, 0), pady=6)
        sb = ttk.Scrollbar(logf, orient='vertical', command=self.log_text.yview)
        sb.grid(row=0, column=1, sticky='ns', padx=(0, 8), pady=6)
        self.log_text.configure(yscrollcommand=sb.set)
        self.log_text.tag_configure('ok', foreground='#7ee787')
        self.log_text.tag_configure('err', foreground='#ff7b72')
        self.log_text.tag_configure('dim', foreground='#8b949e')
        self.log_text.tag_configure('head', foreground='#79c0ff')

        bottom = ttk.Frame(self)
        bottom.grid(row=3, column=0, sticky='ew', padx=10, pady=(0, 8))
        bottom.columnconfigure(0, weight=1)
        ttk.Label(bottom, textvariable=self.status_var).grid(
            row=0, column=0, sticky='w')
        ttk.Button(bottom, text='Clear log',
                   command=self.clear_log).grid(row=0, column=1, padx=4)
        ttk.Button(bottom, text='Exit', command=self.destroy).grid(
            row=0, column=2)

    def _build_info_tab(self) -> None:
        f = self.tab_info
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        self.info_text = tk.Text(f, font=MONO, wrap='word', state='disabled',
                                 relief='flat', background='#f6f8fa')
        self.info_text.grid(row=0, column=0, sticky='nsew')
        sb = ttk.Scrollbar(f, orient='vertical', command=self.info_text.yview)
        sb.grid(row=0, column=1, sticky='ns')
        self.info_text.configure(yscrollcommand=sb.set)
        self.info_text.tag_configure('bad', foreground='#b31d28')

        bar = ttk.Frame(f)
        bar.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(8, 0))
        ttk.Button(bar, text='Unpack…', command=self.do_unpack).grid(
            row=0, column=0, padx=(0, 6))
        ttk.Button(bar, text='Verify', command=self.do_verify).grid(
            row=0, column=1, padx=6)
        ttk.Button(bar, text='Compare with another .chp…',
                   command=self.do_diff).grid(row=0, column=2, padx=6)
        ttk.Button(bar, text='Show HEX',
                   command=self.do_show_hex).grid(row=0, column=3, padx=6)

    def _build_pack_tab(self) -> None:
        f = self.tab_pack
        f.columnconfigure(0, minsize=175)
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text='Modified .bin image').grid(
            row=0, column=0, sticky='w', pady=4)
        ttk.Entry(f, textvariable=self.bin_var).grid(
            row=0, column=1, sticky='ew', padx=6)
        ttk.Button(f, text='Browse…', command=self.pick_bin).grid(
            row=0, column=2, sticky='w')

        ttk.Label(f, text='Output .chp').grid(
            row=1, column=0, sticky='w', pady=4)
        ttk.Entry(f, textvariable=self.pack_out_var).grid(
            row=1, column=1, sticky='ew', padx=6)
        ttk.Button(f, text='Save as…', command=self.pick_pack_out).grid(
            row=1, column=2, sticky='w')

        opt = ttk.LabelFrame(f, text=' Options ')
        opt.grid(row=2, column=0, columnspan=3, sticky='ew', pady=10)
        opt.columnconfigure(7, weight=1)
        ttk.Label(opt, text='subversion:').grid(row=0, column=0, padx=(8, 4), pady=8)
        ttk.Entry(opt, textvariable=self.pack_sub_var, width=8).grid(
            row=0, column=1, sticky='w')
        ttk.Label(opt, text='version:').grid(row=0, column=2, padx=(16, 4))
        ttk.Entry(opt, textvariable=self.pack_ver_var, width=8).grid(
            row=0, column=3, sticky='w')
        ttk.Label(opt, text='inner name:').grid(row=0, column=4, padx=(16, 4))
        ttk.Entry(opt, textvariable=self.pack_name_var, width=28).grid(
            row=0, column=5, columnspan=2, sticky='w')
        ttk.Checkbutton(opt, text='recompute checksum (0x808)',
                        variable=self.pack_fixck_var).grid(
            row=0, column=7, sticky='e', padx=8)

        ttk.Button(f, text='Build .chp', command=self.do_pack).grid(
            row=3, column=0, columnspan=2, sticky='w')
        ttk.Label(f, foreground='#57606a', wraplength=880,
                  text='Differences between the .bin and the image inside the '
                       'source .chp are carried over as HEX without shifting '
                       'addresses; the checksum, CRC and container padding are '
                       'recomputed, and the file is verified by reading it '
                       'back.').grid(row=4, column=0, columnspan=3,
                                     sticky='w', pady=(12, 0))

    def _build_edit_tab(self) -> None:
        f = self.tab_edit
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)

        cols = ('addr', 'old', 'new', 'kind')
        self.tree = ttk.Treeview(f, columns=cols, show='headings', height=8)
        for c, t, w in (('addr', 'address', 110), ('old', 'before', 110),
                        ('new', 'after', 110), ('kind', 'kind', 90)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor='w')
        self.tree.grid(row=0, column=0, sticky='nsew')
        sb = ttk.Scrollbar(f, orient='vertical', command=self.tree.yview)
        sb.grid(row=0, column=1, sticky='ns')
        self.tree.configure(yscrollcommand=sb.set)

        form = ttk.Frame(f)
        form.grid(row=1, column=0, columnspan=2, sticky='ew', pady=8)
        ttk.Label(form, text='address:').grid(row=0, column=0)
        ttk.Entry(form, textvariable=self.edit_addr_var, width=12).grid(
            row=0, column=1, padx=(4, 12))
        ttk.Label(form, text='value:').grid(row=0, column=2)
        ttk.Entry(form, textvariable=self.edit_val_var, width=10).grid(
            row=0, column=3, padx=(4, 12))
        ttk.Combobox(form, textvariable=self.edit_kind_var, width=8,
                     state='readonly', values=('word', 'byte')).grid(
            row=0, column=4)
        ttk.Button(form, text='Add', command=self.add_edit).grid(
            row=0, column=5, padx=(12, 4))
        ttk.Button(form, text='Delete', command=self.del_edit).grid(
            row=0, column=6, padx=4)
        ttk.Button(form, text='Clear', command=self.clear_edits).grid(
            row=0, column=7, padx=4)
        for w in form.winfo_children():
            if isinstance(w, ttk.Entry):
                w.bind('<Return>', lambda e: self.add_edit())

        ttk.Label(f, text='Output .chp').grid(row=2, column=0, sticky='w')
        box = ttk.Frame(f)
        box.grid(row=3, column=0, columnspan=2, sticky='ew')
        box.columnconfigure(0, weight=1)
        ttk.Entry(box, textvariable=self.set_out_var).grid(
            row=0, column=0, sticky='ew')
        ttk.Button(box, text='Save as…', command=self.pick_set_out).grid(
            row=0, column=1, padx=(6, 0))

        opt = ttk.LabelFrame(f, text=' Options ')
        opt.grid(row=4, column=0, columnspan=2, sticky='ew', pady=10)
        ttk.Label(opt, text='subversion:').grid(row=0, column=0, padx=(8, 4), pady=8)
        ttk.Entry(opt, textvariable=self.set_sub_var, width=8).grid(
            row=0, column=1, sticky='w')
        ttk.Label(opt, text='version:').grid(row=0, column=2, padx=(16, 4))
        ttk.Entry(opt, textvariable=self.set_ver_var, width=8).grid(
            row=0, column=3, sticky='w')
        ttk.Label(opt, text='inner name:').grid(row=0, column=4, padx=(16, 4))
        ttk.Entry(opt, textvariable=self.set_name_var, width=28).grid(
            row=0, column=5, sticky='w')
        ttk.Checkbutton(opt, text='recompute checksum (0x808)',
                        variable=self.set_fixck_var).grid(
            row=0, column=6, sticky='e', padx=8)

        ttk.Button(f, text='Build .chp', command=self.do_set).grid(
            row=5, column=0, sticky='w')

    def _bind_keys(self) -> None:
        self.bind('<Control-o>', lambda e: self.pick_src())
        self.bind('<F5>', lambda e: self.reload())

    # ------------------------------------------------------------ service --
    def log(self, msg: str, tag: str | None = None) -> None:
        self.log_text.configure(state='normal')
        self.log_text.insert('end', msg.rstrip() + '\n', tag or ())
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

    def clear_log(self) -> None:
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.configure(state='disabled')

    def set_info(self, text: str, bad_lines: set[int] | None = None) -> None:
        self.info_text.configure(state='normal')
        self.info_text.delete('1.0', 'end')
        for i, line in enumerate(text.splitlines()):
            tag = 'bad' if bad_lines and i in bad_lines else ()
            self.info_text.insert('end', line + '\n', tag)
        self.info_text.configure(state='disabled')

    def guard(self, title: str, fn) -> None:
        try:
            fn()
        except SystemExit as e:
            msg = str(e.code) if e.code is not None else 'stopped'
            self.log('%s: %s' % (title, msg), 'err')
            messagebox.showerror(title, msg)
        except Exception:
            tb = traceback.format_exc()
            self.log(tb, 'err')
            messagebox.showerror(title, tb.strip().splitlines()[-1])

    def require_base(self) -> chp.Container | None:
        if self.base is None:
            path = self.src_var.get().strip()
            if not path:
                messagebox.showinfo('File required', 'Select a .chp file first')
                return None
            self.load(path)
        return self.base

    def _stem(self) -> str:
        return os.path.splitext(os.path.basename(self.base_path))[0]

    def _same_dir(self, suffix: str) -> str:
        d = os.path.dirname(os.path.abspath(self.base_path)) if self.base_path else ''
        return os.path.join(d, self._stem() + suffix + '.chp')

    # ------------------------------------------------------------ loading --
    def pick_src(self) -> None:
        p = filedialog.askopenfilename(title='Open firmware',
                                       filetypes=CHP_TYPES)
        if p:
            self.src_var.set(p)
            self.reload()

    def reload(self) -> None:
        path = self.src_var.get().strip()
        if not path:
            return
        self.guard('Load', lambda: self.load(path))

    def load(self, path: str) -> None:
        c = chp.Container(path)
        self.base = c
        self.base_path = path
        self.src_var.set(path)
        d = c.info()
        self.set_info(self.format_info(d, c))
        if d['kind'] == 'header':
            self.status_var.set('%s — version %d / subversion %d, checksum %04X'
                                % (os.path.basename(path), d['version'],
                                   d['subversion'], d['ck']))
        else:
            self.status_var.set('%s — %d bytes, no 0x800 header'
                                % (os.path.basename(path), len(c.image)))
        if not self.pack_out_var.get():
            self.pack_out_var.set(self._same_dir('_new'))
        if not self.set_out_var.get():
            self.set_out_var.set(self._same_dir('_edit'))
        self.log('Loaded: %s' % path, 'head')
        if d['kind'] == 'header':
            self.log('  version %d / subversion %d, W=0x%05X, sha256 %s'
                     % (d['version'], d['subversion'], d['W'],
                        d['image_sha256'][:16] + '…'))
        else:
            self.log('  image %d bytes (0x%X..0x%X), sha256 %s'
                     % (len(c.image), d['image_lo'], d['image_hi'],
                        d['image_sha256'][:16] + '…'))
        if d['problems']:
            for p in d['problems']:
                self.log('  problem: %s' % p, 'err')
        else:
            self.log('  container: ok', 'ok')

    @staticmethod
    def format_info(d: dict, c: chp.Container) -> str:
        L = []
        L.append('file        : %s' % d['file'])
        L.append('inner name  : %s' % d['name_attr'])
        L.append('size        : %d bytes in file, attribute %d'
                 % (d['file_size'], d['size_attr']))
        L.append('checksum    : %d (crc8 %d)' % (d['kc_attr'], d['kc_crc8']))
        L.append('container   : byte0=%d, padding=%d' % (d['byte0'], d['pad']))
        L.append('area        : %d bytes (0x%X)'
                 % (d['area_size'], d['area_size']))
        L.append('XML         : version %s, subversion %s'
                 % (d.get('xml_version') or '-',
                    d['xml_subversion'] if d.get('xml_subversion') is not None else '-'))
        L.append('')
        L.append('image:')
        if d['kind'] == 'header':
            L.append('  header    : %s' % d['header'])
            L.append('  version   : %d (%.2f), subversion %d'
                     % (d['version'], d['version'] / 100.0, d['subversion']))
            L.append('  W         : 0x%05X' % d['W'])
            L.append('  sum       : %s / sum+2 %s'
                     % ('ok' if d['sum_ok'] else 'BAD',
                        'ok' if d['sum2_ok'] else 'BAD'))
            L.append('  tail      : %04X%s'
                     % (d['tail'] if d['tail'] is not None else -1,
                        '' if d['tail_ok'] else '  (not 0F0F — allowed)'))
        else:
            L.append('  kind      : no 0x800 header (generic)')
            L.append('  range     : 0x%X..0x%X, %d bytes'
                     % (d['image_lo'], d['image_hi'], d['image_size']))
        L.append('  sha256    : %s' % d['image_sha256'])
        L.append('  file      : %s' % d['file_sha256'])
        L.append('')
        if d['problems']:
            L.append('CONTAINER ERRORS:')
            L.extend('  - %s' % p for p in d['problems'])
        else:
            L.append('container   : ok')
        return '\n'.join(L)

    # ------------------------------------------------------------ info tab --
    def do_unpack(self) -> None:
        c = self.require_base()
        if not c:
            return
        base_dir = os.path.dirname(os.path.abspath(self.base_path))
        folder = filedialog.askdirectory(
            title='Where to unpack',
            initialdir=os.path.join(base_dir, self._stem() + '_unpacked'))
        if not folder:
            return

        def run():
            os.makedirs(folder, exist_ok=True)
            stem = self._stem()
            p_bin = os.path.join(folder, stem + '.bin')
            p_xml = os.path.join(folder, stem + '.xml')
            p_hex = os.path.join(folder, stem + '.hex')
            open(p_bin, 'wb').write(c.image)
            open(p_xml, 'w', encoding='utf-8', newline='\n').write(
                c.xml.decode('cp1251', 'replace').replace('\r\n', '\n'))
            open(p_hex, 'w', encoding='ascii', newline='\n').write(
                chp.hex_text(c.xml))
            self.log('Unpacked to %s' % folder, 'ok')
            if c.kind == 'header':
                self.log('  %s — %d bytes (data from 0x800)'
                         % (os.path.basename(p_bin), len(c.image)))
            else:
                self.log('  %s — %d bytes (0x%X..0x%X)'
                         % (os.path.basename(p_bin), len(c.image),
                            c.span[0], c.span[1]))
            self.log('  %s — XML (for reading)' % os.path.basename(p_xml))
            self.log('  %s — HEX block' % os.path.basename(p_hex))
            messagebox.showinfo('Unpacked', folder)

        self.guard('Unpack', run)

    def do_verify(self) -> None:
        c = self.require_base()
        if not c:
            return
        probs = c.check()
        ii = chp.image_info(c.image)
        self.log('Check %s' % os.path.basename(self.base_path), 'head')
        if probs:
            for p in probs:
                self.log('  container: %s' % p, 'err')
        else:
            self.log('  container: ok', 'ok')
        if ii['kind'] == 'header':
            for label, ok, val in (
                    ('sum', ii['sum_ok'], ii.get('sum')),
                    ('sum+2', ii['sum2_ok'], ii.get('sum_plus2'))):
                self.log('  %-8s: %04X %s'
                         % (label, val if val is not None else -1,
                            'ok' if ok else 'BAD'),
                         'ok' if ok else 'err')
            self.log('  tail    : %04X %s'
                     % (ii.get('tail', -1),
                        '' if ii['tail_ok'] else '(not 0F0F)'))
        else:
            self.log('  image   : %d bytes, no 0x800 header'
                     % len(c.image), 'dim')
        if probs or (ii['kind'] == 'header'
                     and (not ii['sum_ok'] or not ii['sum2_ok'])):
            messagebox.showwarning('Verification', 'There are problems, see the log')

    def do_diff(self) -> None:
        c = self.require_base()
        if not c:
            return
        other = filedialog.askopenfilename(title='Compare with…',
                                           filetypes=CHP_TYPES)
        if not other:
            return

        def run():
            c2 = chp.Container(other)
            if len(c.image) != len(c2.image):
                raise SystemExit('image sizes differ')
            diffs = [(i, c.image[i], c2.image[i])
                     for i in range(len(c.image)) if c.image[i] != c2.image[i]]
            self.log('Comparison: %s  ->  %s'
                     % (os.path.basename(self.base_path),
                        os.path.basename(other)), 'head')
            self.log('  differences: %d' % len(diffs))
            for a, o, n in diffs[:500]:
                self.log('  %05X: %02X -> %02X' % (a, o, n))
            if len(diffs) > 500:
                self.log('  … %d more' % (len(diffs) - 500))
            ia, ib = chp.image_info(c.image), chp.image_info(c2.image)
            if ia['kind'] == 'header' and ib['kind'] == 'header':
                self.log('  version/subversion: %d/%d -> %d/%d'
                         % (ia['version'], ia['subversion'],
                            ib['version'], ib['subversion']))
                self.log('  checksum: %04X -> %04X' % (ia['ck'], ib['ck']))
            else:
                self.log('  kind: %s -> %s' % (ia['kind'], ib['kind']))

        self.guard('Comparison', run)

    def do_show_hex(self) -> None:
        c = self.require_base()
        if not c:
            return
        win = tk.Toplevel(self)
        win.title('HEX — %s' % os.path.basename(self.base_path))
        win.geometry('760x600')
        txt = tk.Text(win, font=MONO, wrap='none')
        txt.pack(fill='both', expand=True)
        txt.insert('1.0', chp.hex_text(c.xml))
        txt.configure(state='disabled')

    # -------------------------------------------------------------- build ---
    def pick_bin(self) -> None:
        p = filedialog.askopenfilename(
            title='Modified image',
            filetypes=[('Image', '*.bin'), ('All files', '*.*')])
        if p:
            self.bin_var.set(p)
            if not self.pack_out_var.get():
                self.pack_out_var.set(self._same_dir('_new'))

    def pick_pack_out(self) -> None:
        p = filedialog.asksaveasfilename(
            title='Where to save the .chp', defaultextension='.chp',
            filetypes=CHP_TYPES,
            initialfile=os.path.basename(self.pack_out_var.get() or 'new.chp'))
        if p:
            self.pack_out_var.set(p)

    def pick_set_out(self) -> None:
        p = filedialog.asksaveasfilename(
            title='Where to save the .chp', defaultextension='.chp',
            filetypes=CHP_TYPES,
            initialfile=os.path.basename(self.set_out_var.get() or 'new.chp'))
        if p:
            self.set_out_var.set(p)

    def _opt(self, sub_var: tk.StringVar, ver_var: tk.StringVar,
             name_var: tk.StringVar) -> tuple[int | None, str | None, bytes | None]:
        sub = ver = None
        sub_s = sub_var.get().strip()
        ver_s = ver_var.get().strip()
        if sub_s:
            try:
                sub = int(sub_s, 0)
            except ValueError:
                raise SystemExit('subversion: a number is required, got "%s"' % sub_s)
            if not 0 <= sub <= 0xFFFF:
                raise SystemExit('subversion out of range 0..65535')
        if ver_s:
            ver = ver_s.replace(',', '.')
        name_s = name_var.get().strip()
        name = None
        if name_s:
            try:
                name = name_s.encode('cp1251')
            except UnicodeEncodeError:
                raise SystemExit('name: cp1251 only')
        return sub, ver, name

    def _report(self, res: dict) -> None:
        for a, o, n in res['diffs']:
            self.log('  %05X: %02X -> %02X' % (a, o, n))
        if not res['diffs']:
            self.log('  image unchanged', 'dim')
        if res.get('kind') == 'header':
            self.log('  version/subversion: %d / %d'
                     % (res['version'], res['subversion']))
            self.log('  checksum: %04X, sum %04X (%s), sum+2 %04X (%s)'
                     % (res['ck'], res.get('sum', -1),
                        'ok' if res['sum_ok'] else 'BAD',
                        res.get('sum_plus2', -1),
                        'ok' if res['sum2_ok'] else 'BAD'),
                     'ok' if res['sum_ok'] and res['sum2_ok'] else 'err')
        else:
            self.log('  image: %d bytes, no 0x800 header'
                     % res.get('size', 0), 'dim')
        self.log('  file: %d bytes, sha256 %s'
                 % (os.path.getsize(res['out']),
                    hashlib.sha256(open(res['out'], 'rb').read()).hexdigest()))
        self.status_var.set('built: %s' % res['out'])

    def do_pack(self) -> None:
        c = self.require_base()
        if not c:
            return
        bin_path = self.bin_var.get().strip()
        out = self.pack_out_var.get().strip()
        if not bin_path:
            messagebox.showinfo('Build', 'Specify the modified .bin')
            return
        if not out:
            messagebox.showinfo('Build', 'Specify the output file')
            return

        def run():
            img = open(bin_path, 'rb').read()
            sub, ver, name = self._opt(self.pack_sub_var,
                                       self.pack_ver_var,
                                       self.pack_name_var)
            self.log('Build: %s + %s' % (os.path.basename(self.base_path),
                                         os.path.basename(bin_path)), 'head')
            res = chp.rebuild(c, img, out, name=name, sub=sub, ver=ver,
                              fixck=self.pack_fixck_var.get(), quiet=True)
            self._report(res)
            messagebox.showinfo('Done', out)

        self.guard('Build', run)

    # -------------------------------------------------------------- edits ---
    def add_edit(self) -> None:
        c = self.base
        try:
            addr = chp.parse_addr(self.edit_addr_var.get())
        except ValueError:
            messagebox.showerror('Edit', 'Cannot parse address "%s"'
                                 % self.edit_addr_var.get())
            return
        kind = self.edit_kind_var.get()
        val_s = self.edit_val_var.get().strip()
        try:
            val = int(val_s, 16)
        except ValueError:
            messagebox.showerror('Edit', 'Value must be hexadecimal')
            return
        if kind == 'byte':
            if not 0 <= val <= 0xFF:
                messagebox.showerror('Edit', 'Byte: 00..FF')
                return
            size = 1
        else:
            if not 0 <= val <= 0xFFFF:
                messagebox.showerror('Edit', 'Word: 0000..FFFF')
                return
            size = 2
        if not 0 <= addr < (len(c.image) - size + 1 if c else 0x20000 - size + 1):
            messagebox.showerror('Edit', 'Address outside the image')
            return

        old = '—'
        if c:
            old = ('%02X' % c.image[addr]) if size == 1 \
                else ('%04X' % chp.word(c.image, addr))
        self.edits.append((addr, val, kind))
        shown_new = ('%02X' % val) if size == 1 else ('%04X' % val)
        self.tree.insert('', 'end', values=('0x%05X' % addr, old, shown_new, kind))
        self.log('  + %05X: %s -> %s (%s)' % (addr, old, shown_new, kind), 'dim')
        self.edit_addr_var.set('')
        self.edit_val_var.set('')

    def del_edit(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        self.tree.delete(sel[0])
        del self.edits[idx]

    def clear_edits(self) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.edits.clear()

    def do_set(self) -> None:
        c = self.require_base()
        if not c:
            return
        if not self.edits:
            messagebox.showinfo('Edit', 'The edit list is empty')
            return
        out = self.set_out_var.get().strip()
        if not out:
            messagebox.showinfo('Edit', 'Specify the output file')
            return

        def run():
            img = bytearray(c.image)
            self.log('Build with edits (%d):' % len(self.edits), 'head')
            for addr, val, kind in self.edits:
                if kind == 'byte':
                    self.log('  %05X: %02X -> %02X'
                             % (addr, img[addr], val))
                    img[addr] = val
                else:
                    self.log('  %05X: %04X -> %04X'
                             % (addr, chp.word(img, addr), val))
                    img[addr:addr + 2] = val.to_bytes(2, 'little')
            sub, ver, name = self._opt(self.set_sub_var, self.set_ver_var,
                                       self.set_name_var)
            res = chp.rebuild(c, bytes(img), out, name=name, sub=sub, ver=ver,
                              fixck=self.set_fixck_var.get(), quiet=True)
            self._report(res)
            messagebox.showinfo('Done', out)

        self.guard('Build', run)


def main() -> None:
    app = App()
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    if args and os.path.isfile(args[0]):
        app.guard('Load', lambda: app.load(args[0]))
    if '--selftest' in sys.argv:
        app.update_idletasks()
        app.update()
        app.destroy()
        print('selftest ok')
        return
    app.mainloop()


if __name__ == '__main__':
    main()
