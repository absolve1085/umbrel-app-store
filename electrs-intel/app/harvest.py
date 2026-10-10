#!/usr/bin/env python3
import json, sqlite3, argparse, time
from resolve import Client
from parse_pcap import read_varint, scripthash_of

def tx_io(rawhex):
    try:
        b = bytes.fromhex(rawhex)
        i = 4
        if b[i] == 0 and b[i + 1] != 0:
            i += 2
        n, i = read_varint(b, i)
        ins = []
        for _ in range(n):
            ptxid = b[i:i + 32][::-1].hex()
            vout = int.from_bytes(b[i + 32:i + 36], 'little')
            i += 36
            sl, i = read_varint(b, i)
            i += sl + 4
            ins.append((ptxid, vout))
        m, i = read_varint(b, i)
        outs = []
        for _ in range(m):
            v = int.from_bytes(b[i:i + 8], 'little')
            i += 8
            sl, i = read_varint(b, i)
            outs.append((v, b[i:i + sl]))
            i += sl
        return ins, outs
    except Exception:
        return [], []

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default='snoop.db')
    ap.add_argument('--server', default='127.0.0.1:50001')
    ap.add_argument('--max-tx', type=int, default=50)
    ap.add_argument('--max-prev', type=int, default=20)
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.executescript('''
    create table if not exists txs_raw(txid text primary key, rawhex text);
    create table if not exists wallet_txs(scripthash text, txid text, height int, ts int,
      recv int, spent int, delta int, primary key(scripthash, txid));
    create table if not exists utxos(scripthash text, txid text, vout int, value int,
      height int, primary key(scripthash, txid, vout));
    ''')
    host, port = a.server.rsplit(':', 1)
    c = Client((host, int(port)))
    hcache = {}

    def get_raw(txid):
        r = con.execute('select rawhex from txs_raw where txid=?', (txid,)).fetchone()
        if r:
            return r[0]
        raw = c.call('blockchain.transaction.get', [txid, False])
        if isinstance(raw, str):
            con.execute('insert or replace into txs_raw values(?,?)', (txid, raw))
        return raw

    def height_ts(h):
        if h not in hcache:
            try:
                hx = c.call('blockchain.block.header', [h])
                hcache[h] = int.from_bytes(bytes.fromhex(hx)[68:72], 'big') if hx else None
            except Exception:
                hcache[h] = None
        return hcache[h]

    ntx = nsh = 0
    for (sh,) in con.execute('select scripthash from scripthashes').fetchall():
        nsh += 1
        for u in (c.call('blockchain.scripthash.listunspent', [sh]) or []):
            con.execute('insert or replace into utxos values(?,?,?,?,?)',
                        (sh, u['tx_hash'], u['tx_pos'], u['value'], u.get('height') or 0))
        for h in (c.call('blockchain.scripthash.get_history', [sh]) or [])[:a.max_tx]:
            txid = h['tx_hash']
            height = h.get('height') or 0
            raw = get_raw(txid)
            if not isinstance(raw, str):
                continue
            ins, outs = tx_io(raw)
            recv = sum(v for v, s in outs if scripthash_of(s) == sh)
            spent = 0
            for ptxid, vout in ins[:a.max_prev]:
                praw = get_raw(ptxid)
                if not isinstance(praw, str):
                    continue
                _, pouts = tx_io(praw)
                if vout < len(pouts) and scripthash_of(pouts[vout][1]) == sh:
                    spent += pouts[vout][0]
            con.execute('insert or replace into wallet_txs values(?,?,?,?,?,?,?)',
                        (sh, txid, height, height_ts(height), recv, spent, recv - spent))
            ntx += 1
        con.commit()
    c.s.close()
    print('wallets:', nsh, '| txs con detalle:', ntx,
          '| utxos:', con.execute('select count(*) from utxos').fetchone()[0])

if __name__ == '__main__':
    main()
