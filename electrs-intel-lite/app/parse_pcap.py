#!/usr/bin/env python3
import json, sqlite3, struct, sys, glob, os, hashlib, time, argparse

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def bech32_polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def convertbits(data, frm, to, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    return ret


def segwit_addr(hrp, ver, prog):
    const = 1 if ver == 0 else 0x2bc830a3
    data = [ver] + convertbits(prog, 8, 5)
    values = hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0] * 6) ^ const
    return hrp + '1' + ''.join(CHARSET[d] for d in data) + ''.join(
        CHARSET[(polymod >> 5 * (5 - i)) & 31] for i in range(6))


def b58check(verbyte, payload):
    data = bytes([verbyte]) + payload
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n = int.from_bytes(data, 'big')
    s = ''
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return '1' * pad + s


def scripthash_of(script):
    return hashlib.sha256(script).digest()[::-1].hex()


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    h = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    pad = 0
    for c in s:
        if c == '1':
            pad += 1
        else:
            break
    return b'\x00' * pad + h


def b58check_decode(s):
    raw = b58decode(s)
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        raise ValueError('checksum base58')
    return payload[0], payload[1:]


def bech32_decode_addr(addr):
    a = addr.lower()
    pos = a.rfind('1')
    hrp = a[:pos]
    data = [CHARSET.index(c) for c in a[pos + 1:]]
    for const in (1, 0x2bc830a3):
        if bech32_polymod(hrp_expand(hrp) + data) == const:
            ver = data[0]
            acc = 0
            bits = 0
            prog = []
            for v in data[1:-6]:
                acc = (acc << 5) | v
                bits += 5
                while bits >= 8:
                    bits -= 8
                    prog.append((acc >> bits) & 255)
            return ver, bytes(prog), hrp
    raise ValueError('bech32 invalido')


def addr_to_script(addr):
    if addr.lower().startswith(('bc1', 'tb1', 'bcrt1')):
        ver, prog, _ = bech32_decode_addr(addr)
        op = 0x00 if ver == 0 else 0x50 + ver
        return bytes([op, len(prog)]) + prog
    v, h = b58check_decode(addr)
    if v == 0x00:
        return bytes.fromhex('76a914') + h + bytes.fromhex('88ac')
    if v == 0x05:
        return bytes.fromhex('a914') + h + bytes.fromhex('87')
    raise ValueError('version base58 desconocida')


def script_to_address(script):
    if len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[-2:] == b'\x88\xac':
        return b58check(0, script[3:23])
    if len(script) == 23 and script[0] == 0xa9 and script[-1] == 0x87:
        return b58check(5, script[2:22])
    if len(script) == 22 and script[0] == 0 and script[1] == 20:
        return segwit_addr('bc', 0, script[2:])
    if len(script) == 34 and script[0] == 0 and script[1] == 32:
        return segwit_addr('bc', 0, script[2:])
    if len(script) == 34 and script[0] == 0x51 and script[1] == 32:
        return segwit_addr('bc', 1, script[2:])
    return None


def read_varint(b, i):
    n = b[i]
    i += 1
    if n < 0xfd:
        return n, i
    if n == 0xfd:
        return int.from_bytes(b[i:i + 2], 'little'), i + 2
    if n == 0xfe:
        return int.from_bytes(b[i:i + 4], 'little'), i + 4
    return int.from_bytes(b[i:i + 8], 'little'), i + 8


def tx_output_scripts(rawhex):
    try:
        b = bytes.fromhex(rawhex)
        i = 4
        if b[i] == 0 and b[i + 1] != 0:
            i += 2
        n, i = read_varint(b, i)
        for _ in range(n):
            i += 36
            sl, i = read_varint(b, i)
            i += sl + 4
        m, i = read_varint(b, i)
        outs = []
        for _ in range(m):
            i += 8
            sl, i = read_varint(b, i)
            outs.append(b[i:i + sl])
            i += sl
        return outs
    except Exception:
        return []


def iter_pcap(path):
    data = open(path, 'rb').read()
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        endian = '>'
    elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        endian = '<'
    else:
        raise ValueError('no es pcap clasico: ' + path)
    ns = magic in (b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1')
    link = struct.unpack(endian + 'I', data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts, tus, capl, _ = struct.unpack(endian + 'IIII', data[off:off + 16])
        yield ts + tus / (1e9 if ns else 1e6), link, data[off + 16:off + 16 + capl]
        off += 16 + capl


def ip_payload(link, pkt):
    if link == 1:
        if len(pkt) < 34 or pkt[12:14] != b'\x08\x00':
            return None
        return pkt[14:]
    if link == 113:
        if len(pkt) < 20 or pkt[14:16] != b'\x08\x00':
            return None
        return pkt[16:]
    if link == 276:
        if len(pkt) < 20 or pkt[:2] != b'\x08\x00':
            return None
        return pkt[20:]
    if link in (101, 12, 14):
        return pkt
    return None


def parse_tcp(pkt):
    if len(pkt) < 40 or pkt[0] >> 4 != 4 or pkt[9] != 6:
        return None
    ihl = (pkt[0] & 0xf) * 4
    src = '.'.join(str(x) for x in pkt[12:16])
    dst = '.'.join(str(x) for x in pkt[16:20])
    t = pkt[ihl:]
    if len(t) < 20:
        return None
    sport, dport = struct.unpack('!HH', t[:4])
    seq = struct.unpack('!I', t[4:8])[0]
    doff = (t[12] >> 4) * 4
    if doff < 20 or len(t) < doff:
        return None
    return src, sport, dst, dport, seq, t[doff:]


ELECTRUM_PORT = 50001
NOISE_METHODS = {'server.ping', 'server.banner', 'server.donations_url',
                 'server.peers.subscribe', 'blockchain.headers.subscribe'}
LOCAL_IPS = {'127.0.0.1', '::1'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default='snoop.db')
    ap.add_argument('--port', type=int, default=ELECTRUM_PORT)
    ap.add_argument('inputs', nargs='+')
    a = ap.parse_args()

    files = []
    for arg in a.inputs:
        if os.path.isdir(arg):
            files += sorted(glob.glob(os.path.join(arg, '*.pcap*')))
        else:
            files.append(arg)

    con = sqlite3.connect(a.db)
    con.executescript('''
    create table if not exists conns(
      id integer primary key, ip text, port integer, first_ts real, last_ts real,
      n_reqs integer default 0, user_agent text);
    create unique index if not exists conns_ip_port on conns(ip,port);
    create table if not exists requests(
      id integer primary key, conn_id integer, ts real, method text,
      params text, resp text);
    create table if not exists scripthashes(
      scripthash text primary key, first_seen real, last_seen real,
      n_seen integer default 0, address text,
      balance_conf integer, balance_unconf integer, resolved_at real);
    create table if not exists txs(
      txid text primary key, ts real, ip text, rawhex text);
    create table if not exists addresses(
      address text primary key, scripthash text, source text, first_seen real);
    ''')

    flows = {}
    def conn_of(cip, cport):
        r = con.execute('select id from conns where ip=? and port=?', (cip, cport)).fetchone()
        if r:
            return r[0]
        cur = con.execute('insert into conns(ip,port) values(?,?)', (cip, cport))
        return cur.lastrowid

    reqs = []
    resps = {}
    txs = []

    for path in files:
        for ts, link, pkt in iter_pcap(path):
            ip = ip_payload(link, pkt)
            if ip is None:
                continue
            tcp = parse_tcp(ip)
            if tcp is None:
                continue
            src, sport, dst, dport, seq, payload = tcp
            if not payload or (sport != a.port and dport != a.port):
                continue
            if src in LOCAL_IPS:
                continue
            key = (src, sport, dst, dport)
            st = flows.get(key)
            if st is None or seq > st['expected']:
                st = flows[key] = {'expected': seq, 'buf': b''}
            elif seq < st['expected']:
                end = seq + len(payload)
                if end <= st['expected']:
                    continue
                payload = payload[end - (end - st['expected']):]
            st['expected'] = max(st['expected'], seq + len(payload))
            st['buf'] += payload
            if b'\n' not in st['buf']:
                continue
            lines = st['buf'].split(b'\n')
            st['buf'] = lines.pop()
            for line in lines:
                line = line.strip(b'\r \x00')
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                if 'method' in obj and dport == a.port:
                    if obj.get('method') not in NOISE_METHODS:
                        reqs.append((ts, src, sport, obj, key))
                elif 'id' in obj and sport == a.port and ('result' in obj or 'error' in obj):
                    ck = tuple(sorted([key[:2], key[2:]]))
                    rid = obj['id']
                    if isinstance(rid, str) and ':' in rid:
                        rid = rid.split(':', 1)[1]
                    resps[(ck, str(rid))] = obj

    now = time.time()
    for ts, cip, cport, obj, key in reqs:
        cid = conn_of(cip, cport)
        method = obj.get('method', '')
        params = json.dumps(obj.get('params'), ensure_ascii=False)
        rid = obj.get('id')
        ck = tuple(sorted([key[:2], key[2:]]))
        resp = None
        if rid is not None:
            r = resps.get((ck, str(rid)))
            if r:
                resp = json.dumps(r.get('result', r.get('error')), ensure_ascii=False)
        con.execute('insert into requests(conn_id,ts,method,params,resp) values(?,?,?,?,?)',
                    (cid, ts, method, params, resp))
        con.execute('update conns set n_reqs=n_reqs+1, last_ts=max(coalesce(last_ts,0),?) where id=?', (ts, cid))
        con.execute('update conns set first_ts=? where id=? and (first_ts is null or first_ts>?)', (ts, cid, ts))
        if method == 'server.version':
            p = obj.get('params') or []
            if p:
                con.execute('update conns set user_agent=? where id=?', (str(p[0]), cid))
        if 'scripthash' in method:
            p = obj.get('params') or []
            for v in (p if isinstance(p, list) else []):
                if isinstance(v, str) and len(v) == 64:
                    con.execute('''insert into scripthashes(scripthash,first_seen,last_seen,n_seen)
                      values(?,?,?,1) on conflict(scripthash) do update set
                      last_seen=max(last_seen,?), n_seen=n_seen+1''', (v, ts, ts, ts))
        if 'get_balance' in method:
            p = obj.get('params') or []
            if p and resp:
                try:
                    r = json.loads(resp)
                    if isinstance(r, dict):
                        con.execute('''update scripthashes set balance_conf=?, balance_unconf=?, resolved_at=?
                          where scripthash=?''', (r.get('confirmed'), r.get('unconfirmed'), now, p[0]))
                except Exception:
                    pass
        if method == 'transaction.broadcast':
            p = obj.get('params') or []
            if p and isinstance(p[0], str):
                raw = p[0]
                txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex()
                con.execute('insert or ignore into txs(txid,ts,ip,rawhex) values(?,?,?,?)',
                            (txid, ts, cip, raw))
                for script in tx_output_scripts(raw):
                    addr = script_to_address(script)
                    sh = scripthash_of(script)
                    if addr:
                        con.execute('''insert into addresses(address,scripthash,source,first_seen)
                          values(?,?,?,?) on conflict(address) do nothing''', (addr, sh, 'broadcast', ts))
                        con.execute('update scripthashes set address=? where scripthash=?', (addr, sh))
    con.commit()
    con.execute('''update scripthashes set address=(
      select address from addresses where addresses.scripthash=scripthashes.scripthash)
      where address is null''')
    con.commit()
    for q in ['select count(*) from conns', 'select count(*) from requests',
              'select count(*) from scripthashes', 'select count(*) from txs',
              'select count(*) from addresses']:
        print(q.split()[-1], con.execute(q).fetchone()[0])


if __name__ == '__main__':
    main()
