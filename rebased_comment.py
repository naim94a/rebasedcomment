"""
comment rebaser plugin for IDA
Copyright (C) 2020 Naim Abda <naim@abda.nl>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
__version__ = "0.1.0"

import re
import ida_idaapi
import idaapi
import ida_idp
import ida_hexrays
from ida_idaapi import plugin_t
from idaapi import BADADDR, get_cmt

RE_COMMENT = re.compile(r'(?<!\w)((0x[A-f\d]+)|([A-f\d]+h))(?!\w)')

def get_all_comments(seg=None):
    start = 0 if not seg else seg.start_ea
    end = -1 if not seg else seg.end_ea
    while True:
        res = idaapi.next_that(start, end, lambda f: f & idaapi.FF_COMM)
        if res == BADADDR:
            return
        start = res + 1
        yield res

def is_addr(segs, ea):
    for seg in segs:
        s = seg.start_ea
        e = seg.end_ea
        if e > ea >= s:
            return True
    return False

def get_segs():
    seg_count = idaapi.get_segm_qty()
    ranges = []

    for i in range(0, seg_count):
        seg = idaapi.getnseg(i)
        ranges.append(seg)

    return ranges

def rebase_comment(segs, delta, comment):
    res = RE_COMMENT.finditer(comment)
    if not res:
        return None

    spans = []

    for match in res:
        span = match.span()
        s_addr = match.string[span[0]:span[1]]
        h_at = s_addr[0] == '@'
        if h_at:
            s_addr = s_addr[1:]

        h_tail = s_addr[-1] == 'h'
        if h_tail:
            s_addr = s_addr[:-1]
        else:
            s_addr = s_addr[2:]

        addr = int(s_addr, 16)
        fixed_addr = addr + delta

        # This will happen after segments have changed...
        if not is_addr(segs, fixed_addr):
            continue

        new_str = hex(fixed_addr)[2:]
        if new_str[-1] == 'L':
            new_str = new_str[:-1]

        if h_tail:
            new_str += 'h'
        else:
            new_str = '0x' + new_str

        if h_at:
            new_str = '@' + new_str
        
        spans.append((span, new_str))

    if not len(spans):
        return None
    
    fragments = []
    pos = 0
    for (idx, (span, newval)) in enumerate(spans):
        pre = comment[:span[0]][pos:]
        pos = span[1]

        fragments.append(pre)
        fragments.append(newval)

        if idx == len(spans) - 1:
            fragments.append(comment[pos:])
    res = ''.join(fragments)
    return res

def handle_comments(delta, segs):
    for cmt_offset in get_all_comments():
        for is_repeatable in (True, False):
            cmt = idaapi.get_cmt(cmt_offset, is_repeatable)
            if not cmt:
                continue
            new_cmt = rebase_comment(segs, delta, cmt)
            if not new_cmt:
                continue
            idaapi.set_cmt(cmt_offset, new_cmt, is_repeatable)

def handle_structs(delta, segs):
    for idx in range(idaapi.get_struc_qty()):
        tid = idaapi.get_struc_by_idx(idx)
        for cmt_type in (True, False):
            cmt = idaapi.get_struc_cmt(tid, cmt_type)
            if cmt:
                new_cmt = rebase_comment(segs, delta, cmt)
                if new_cmt:
                    idaapi.set_struc_cmt(tid, new_cmt, cmt_type)
        s = idaapi.get_struc(tid)
        for midx in range(s.memqty):
            m = s.get_member(midx)
            for cmt_type in (True, False):
                cmt = idaapi.get_member_cmt(m.id, cmt_type)
                if cmt:
                    new_cmt = rebase_comment(segs, delta, cmt)
                    if new_cmt:
                        idaapi.set_member_cmt(m, new_cmt, cmt_type)


class enum_memb_visitor(idaapi.enum_member_visitor_t):
    def __init__(self, segs, delta):
        super(enum_memb_visitor, self).__init__()
        self.segs = segs
        self.delta = delta

    def visit_enum_member(self, cid, val):
        for cmt_type in (True, False):
            cmt = idaapi.get_enum_member_cmt(cid, cmt_type)
            if cmt:
                new_cmt = rebase_comment(self.segs, self.delta, cmt)
                if new_cmt:
                    idaapi.set_enum_member_cmt(cid, new_cmt, cmt_type)
        return 0

def handle_enums(delta, segs):
    for idx in range(idaapi.get_enum_qty()):
        e = idaapi.getn_enum(idx)
        for cmt_type in (True, False):
            cmt = idaapi.get_enum_cmt(e, cmt_type)
            if cmt:
                new_cmt = rebase_comment(segs, delta, cmt)
                if new_cmt:
                    idaapi.set_enum_cmt(e, new_cmt, cmt_type)
        idaapi.for_all_enum_members(e, enum_memb_visitor(segs, delta))

def get_all_funcs():
    for idx in range(idaapi.get_func_qty()):
        f = idaapi.getn_func(idx)
        yield f

def handle_function_comments(delta, segs):
    for f in get_all_funcs():
        for cmt_type in (True, False):
            cmt = idaapi.get_func_cmt(f, cmt_type)
            if cmt:
                new_cmt = rebase_comment(segs, delta, cmt)
                if new_cmt:
                    idaapi.set_func_cmt(f, cmt, cmt_type)
        cmts = idaapi.restore_user_cmts(f.start_ea)
        if not cmts:
            continue
        changed = False
        for (treeloc, citm) in cmts.items():
            if citm:
                citm = citm.c_str()
            new_cmt = rebase_comment(segs, delta, citm)
            if new_cmt:
                changed = True
                it = cmts.find(treeloc)
                cmts.erase(it)
                cmts.insert(treeloc, idaapi.citem_cmt_t(new_cmt))
        if changed:
            idaapi.save_user_cmts(f.start_ea, cmts)

def patch_comments(delta, affected_segs=None):
    segs = affected_segs if affected_segs else get_segs()

    # Process structs
    handle_structs(delta, segs)

    # Process enums
    handle_enums(delta, segs)

    # Process comments
    handle_comments(delta, segs)

    # process function comments
    handle_function_comments(delta, segs)


class Hooks(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
    
    def allsegs_moved(self, info):
        # TODO: check that all segments actually moved by the same delta.
        seg_info = info.at(0)
        old_base = seg_info._from
        new_base = seg_info.to

        delta = new_base - old_base
        if delta == 0:
            return 0

        patch_comments(delta)

        return 0


class RebasedComment(plugin_t):
    flags = ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_HIDE
    comment = "Updates offsets in comments when rebased"
    wanted_name = "rebasedcomment"
    wanted_hotkey = ""
    help = ""

    def __init__(self):
        pass
    
    def init(self):
        self._hook = Hooks()
        self._hook.hook()
        
        addon = idaapi.addon_info_t()
        addon.id = "naim94a.oss.rebasedcomment"
        addon.url = "https://abda.nl/?rebasedcomment"
        addon.version = __version__
        addon.producer = "Naim A. <naim@abda.nl>"
        addon.freeform = "Copyright (C) 2020 Naim A."
        addon.name = "RebasedComment"
        idaapi.register_addon(addon)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        return 1
    
    def term(self):
        self._hook.unhook()
        pass


def PLUGIN_ENTRY():
    return RebasedComment()
