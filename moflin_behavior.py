#!/usr/bin/env python3
"""
moflin_behavior.py — Moflin behavior container reader/parser
=============================================================

Reads `behavior_XXXXXXXX_decoded.bin` style containers (the binary payload
the MofLife app downloads and flashes to the robot over BLE).

Container layout (reverse-engineered, see update_mechanism_notes.md):

  [root header "DA"]  u16 idx, "DA", ..., u32 total_size @+10, name(16) @+0x10
  then typed sections, each: 32-byte header
      [u16 idx][tag(2)][u8 ver][u8 flags][u32 ?][u32 count][u32 count]
      [16-byte name e.g. "ActList_20240606"][tail: u32 ?, u32 ?, u32 ver]
  and inside each section, a file table of 32-byte records:
      [u32 rel_offset][u32 size][0][0]  followed by [16-byte name]
      (meta comes BEFORE the name; offset is relative to section start)

  Known sections/tags:
    SL "ActList_..."   action tables      -> files "List_N.txt"   (bytecode-ish)
    BC "ActCB_..."     condition blocks  -> files "CB_NN_<behavior>" (8-u32 rows)
    TM "Mot_#NN-..."   motion tables     -> files <motion>.txt/.bin (keyframes)
    VW "Wav_#NN-..."   wave index        -> entries point into wave region
    (wave region after VW: raw RIFF/WAVE PCM 8-bit mono 16 kHz)

File formats:
  MotionScript (.txt/.bin in TM):
      u32 count, [pad 12], then count * (u32 a, u32 b, u32 c)
      Hypothesis: (duration/param, value_from, value_to) keyframes.
  ActList "List_N.txt":
      stream of 16-byte records; byte0 = opcode, rest raw (VM to reverse).
  ActCB "CB_*":
      rows of 8 u32: [(row<<16|row), param_a, param_b, 0, 0, 0, 0, 0]
  Everything else: raw.

Usage:
  python moflin_behavior.py info   <container>
  python moflin_behavior.py ls     <container> [SL|BC|TM0|...]
  python moflin_behavior.py extract <container> <outdir>
  python moflin_behavior.py show   <container> <file-name-substring>
  python moflin_behavior.py wav    <container> <outdir>     # extract all embedded WAVs
"""
import struct, sys, os, re, glob

TAGS = (b'SL', b'BC', b'TM', b'VW', b'DA')

# ---------------------------------------------------------------- container

def u16(d, o): return struct.unpack_from('<H', d, o)[0]
def u32(d, o): return struct.unpack_from('<I', d, o)[0]

def parse_header(d):
    if d[2:4] != b'DA':
        raise ValueError("not a behavior container (no 'DA' magic)")
    return {
        'version': u32(d, 4),
        'total_size': u32(d, 8),
        'name': d[0x10:0x20].split(b'\x00')[0].decode(),
    }

def find_sections(d):
    """Locate section headers. Verified shape (32 bytes):
        [u16 idx][tag 2B][u32 version][u32 size][u32 size] + [16-byte name]
    e.g. TM0: 0000 'TM' 00000010 0000a000 0000a000 'Mot_#20-20240606'
    The root 'DA' header uses the same shape (its size field = whole file).
    """
    secs = []
    for p in range(0, len(d) - 32, 4):
        tag = d[p+2:p+4]
        if tag not in TAGS:
            continue
        idx = u16(d, p)
        ver = u32(d, p+4)
        size = u32(d, p+8)
        name = d[p+16:p+32].split(b'\x00')[0]
        if idx >= 0x100:
            continue
        if ver > 0x100 or size > len(d):
            continue
        if size != u32(d, p+12):
            continue
        if len(name) < 4 or not all(0x20 <= c < 0x7f for c in name):
            continue
        secs.append({
            'off': p, 'tag': tag.decode(), 'idx': idx,
            'ver': ver, 'size': size, 'name': name.decode(),
        })
    return secs

def section_span(d, secs, i):
    s = secs[i]
    end = secs[i+1]['off'] if i+1 < len(secs) else len(d)
    # VW/TM sections may be followed by raw wave data; keep span but clamp to name hint
    return s['off'], end

# ---------------------------------------------------------------- file table

def valid_name(n):
    n = n.split(b'\x00')[0]
    return len(n) >= 3 and all(0x20 <= c < 0x7f for c in n)

def parse_filetable(d, base, end):
    """Yield (off, size, name) for every 32B record [meta][name] inside [base,end)."""
    entries, p = [], base
    while p < end - 32:
        if d[p] == 0x3a:  # ':' file-name prefix
            raw = d[p:p+16]
            if valid_name(raw):
                off, size = struct.unpack_from('<2I', d, p - 16)
                span = end - base
                if off <= span and 0 < size <= span and off + size <= span:
                    entries.append((off, size, raw.split(b'\x00')[0].decode()))
                    p += 32
                    continue
        p += 2
    return entries

def parse_container(path):
    d = open(path, 'rb').read()
    hdr = parse_header(d)
    secs = find_sections(d)
    # compute spans (section end = next section start; VW ends at wave region)
    for i, s in enumerate(secs):
        end = secs[i+1]['off'] if i+1 < len(secs) else len(d)
        s['start'] = s['off']
        s['end'] = end
    for s in secs:
        if s['tag'] in ('SL', 'BC', 'TM'):
            s['files'] = parse_filetable(d, s['start'], s['end'])
        elif s['tag'] == 'VW':
            # wave region = first RIFF/WAVE after the VW table
            wstart = None
            q = s['start'] + 0x100
            while q < len(d) - 12:
                if d[q:q+4] == b'RIFF' and d[q+8:q+12] == b'WAVE':
                    wstart = q
                    break
                q += 2
            s['wstart'] = wstart
            entries = []
            if wstart:
                p = s['start']
                while p < wstart - 32:
                    if d[p] == 0x3a and valid_name(d[p:p+16]):
                        off, size = struct.unpack_from('<2I', d, p - 16)
                        if wstart + off + size <= len(d) and d[wstart+off:wstart+off+4] == b'RIFF':
                            entries.append((off, size, d[p:p+16].split(b'\x00')[0].decode()))
                        p += 32
                    else:
                        p += 2
            s['files'] = entries
    return d, hdr, secs

# ---------------------------------------------------------------- decoders

def decode_motion(d):
    """Motion script (VERIFIED format):
        u32 n; u32 zero[3]; (n-1) * { u32 dt_ms; u32 pos_a; u32 pos_b }
    Keyframes chain positions of two channels; dt = ms to next frame.
    Exact-fit check: len == 16 + (n-1)*12.
    """
    if len(d) < 16:
        return None
    n = u32(d, 0)
    if n < 2 or n > 4096:
        return None
    frames_n = n - 1
    if len(d) != 16 + frames_n * 12:
        return None
    if any(d[4:16]):
        return None  # 12-byte pad must be zero
    frames = [struct.unpack_from('<3I', d, 16 + i*12) for i in range(frames_n)]
    return {'n': n, 'frames': frames}

def decode_actcb(d):
    """ActCB: rows of 8 u32s, row index packed as (i<<16|i)."""
    rows = []
    for o in range(0, len(d) - 31, 32):
        rows.append(struct.unpack_from('<8I', d, o))
    return rows

def decode_actlist(d):
    """ActList entry stream (32-byte rows). Reverse-engineered so far:

    Row = [b0][refs...][terminator 0xff][params...]
      - b0: entry index within the list (0,1,2,... sequential)
      - refs: 3-byte records, TWO variants observed:
            (id u16, type u8)   -- most common (fits 522/626 rows cleanly)
            (type u8, id u8, param u8) -- variant rows
      - ref types:  0x14 = motion/script reference (id often tbl<<8|file_id)
                    0x15 = unknown (LED/eye? sub-call?)
                    0x16 = play sound  (ids 0-106 = VW wave index; VERIFIED:
                            List_23 'KubiNade' plays sounds 45-62 = natuki/
                            sakebi/kuse bonding sounds)
      - 0xff terminates the ref list; remaining bytes = params
      - ActCB rows reference these lists: (0x14, List_N) e.g. KubiNade CB
        -> List_23, Oyasumi CB -> List_21 (chain: sensor CB -> List -> motions+sounds)
    Returns list of dicts.
    """
    entries = []
    for o in range(0, len(d) - 31, 32):
        r = d[o:o+32]
        refs_main, p = [], 1
        while p + 2 < 16:
            t = r[p+2]
            if t == 0xff:
                break
            if t in (0x14, 0x15, 0x16):
                refs_main.append({'kind': 'id16', 'id': r[p] | r[p+1] << 8, 'type': t})
            else:
                refs_main.append({'kind': 'raw', 'bytes': r[p:p+3].hex()})
            p += 3
        entries.append({
            'index': r[0],
            'refs': refs_main,
            'terminated': p < 16 and r[p] == 0xff,
            'tail': r[p:].hex(' '),
            'raw': r.hex(' '),
        })
    return entries

def show_motion(m, name):
    print(f"motion '{name}': n={m['n']} -> {len(m['frames'])} keyframes (dt_ms, pos_a, pos_b)")
    for i, (dt, a, b) in enumerate(m['frames']):
        print(f"  [{i:3d}] dt={dt:<6d} pos_a={a:<6d} pos_b={b:<6d}")

def show_actcb(rows, name):
    print(f"actcb '{name}': {len(rows)} rows")
    for i, r in enumerate(rows):
        print(f"  [{i:3d}] idx={r[0]:#010x} param_a={r[1]:#010x} param_b={r[2]:#010x} rest={r[3:]}")

def show_actlist(recs, name):
    print(f"actlist '{name}': {len(recs)} entries")
    KIND = {0x14: 'motion', 0x15: 'unk15', 0x16: 'sound'}
    for e in recs[:40]:
        parts = []
        for rf in e['refs']:
            if rf['kind'] == 'id16':
                parts.append(f"{KIND.get(rf['type'], hex(rf['type']))}:{rf['id']}")
            else:
                parts.append(f"raw({rf['bytes']})")
        term = '' if e['terminated'] else ' !NOTERM'
        print(f"  [{e['index']:3d}] {' '.join(parts) or '-'}{term}  tail={e['tail']}")
    if len(recs) > 40:
        print(f"  ... {len(recs)-40} more")

def auto_show(path):
    """Show a single extracted file with auto-detected decoding."""
    d = open(path, 'rb').read()
    base = os.path.basename(path)
    if d[:4] == b'RIFF':
        print(f"{base}: RIFF/WAVE {len(d)} bytes")
        return
    m = decode_motion(d)
    if m:
        show_motion(m, base)
        return
    if base.startswith('BC_'):
        show_actcb(decode_actcb(d), base)
        return
    if 'List_' in base:
        show_actlist(decode_actlist(d), base)
        return
    print(f"{base}: {len(d)} bytes (raw)")
    for r in range(0, min(len(d), 64), 16):
        row = d[r:r+16]
        print(f"  {r:06x}  {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")

# ---------------------------------------------------------------- CLI

def sanitize(n):
    return re.sub(r'[^A-Za-z0-9._-]', '_', n.strip(':')).strip('_') or 'unnamed'

def cmd_info(container):
    d, hdr, secs = parse_container(container)
    print(f"container: {container}")
    print(f"  name={hdr['name']}  version={hdr['version']:#010x}  "
          f"size_field={hdr['total_size']:#x} actual={len(d):#x}")
    for s in secs:
        n = len(s.get('files', []))
        print(f"  [{s['idx']:3d}] {s['tag']} @{s['start']:#08x}-{s['end']:#08x} "
              f"size={s['size']:#8x} '{s['name']}' files={n}")

def cmd_ls(container, flt=None):
    d, hdr, secs = parse_container(container)
    for s in secs:
        if flt and flt.upper() != s['tag'] and flt.upper() not in s['name']:
            continue
        for off, size, name in s.get('files', []):
            print(f"{s['tag']:3s} {name:16s} off={off:#08x} size={size}")

def cmd_extract(container, outdir):
    d, hdr, secs = parse_container(container)
    os.makedirs(outdir, exist_ok=True)
    manifest = []
    # named files
    for s in secs:
        for off, size, name in s.get('files', []):
            if s['tag'] == 'VW':
                wstart = s['wstart']
                data = d[wstart+off:wstart+off+size]
                fn = f"VW_{sanitize(name)}.wav"
            else:
                data = d[s['start']+off:s['start']+off+size]
                ext = '.txt' if name.strip(':').endswith('txt') else '.bin'
                fn = f"{s['tag']}_{sanitize(name)}{ext}"
            open(os.path.join(outdir, fn), 'wb').write(data)
            manifest.append(f"{s['tag']}\t{name}\t{off:#x}\t{size}\t{fn}")
    # wave region: carve any RIFF not covered by the index
    vw = [s for s in secs if s['tag'] == 'VW']
    if vw:
        wstart = vw[0]['end']
        i, n = 0, 0
        while True:
            i = d.find(b'RIFF', i)
            if i == -1:
                break
            if i+12 <= len(d) and d[i+8:i+12] == b'WAVE':
                size = u32(d, i+4)
                fn = os.path.join(outdir, f"VW_raw_{n:03d}_at_{i:06x}.wav")
                open(fn, 'wb').write(d[i:i+8+size])
                n += 1
            i += 4
        print(f"wave region: carved {n} RIFF/WAVE files")
    open(os.path.join(outdir, 'MANIFEST.txt'), 'w').write("\n".join(manifest))
    print(f"extracted {len(manifest)} named files -> {outdir}")

def cmd_show(container, needle):
    d, hdr, secs = parse_container(container)
    for s in secs:
        for off, size, name in s.get('files', []):
            if needle.lower() in name.lower():
                wstart = s.get('wstart', s['start']) if s['tag'] == 'VW' else s['start']
                data = d[wstart+off:wstart+off+size]
                # fake a filename so auto_show can detect the type
                ext = '.txt' if name.strip(':').endswith('txt') else '.bin'
                fake = os.path.join(f"{s['tag']}_{sanitize(name)}{ext}")
                open(fake, 'wb').write(data)
                try:
                    auto_show(fake)
                finally:
                    os.remove(fake)
                return
    # maybe it's a wav by index name
    print(f"no file matching '{needle}'")

def cmd_wav(container, outdir):
    cmd_extract(container, outdir)

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == 'info':
        cmd_info(sys.argv[2])
    elif cmd == 'ls':
        cmd_ls(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == 'extract':
        cmd_extract(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else 'behavior_extract2')
    elif cmd == 'show':
        cmd_show(sys.argv[2], sys.argv[3])
    elif cmd == 'wav':
        cmd_wav(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else 'wavs')
    else:
        print(__doc__)
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())
