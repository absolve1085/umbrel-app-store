#!/usr/bin/env python3
import socket, json, sqlite3, argparse, time
from parse_pcap import tx_output_scripts, script_to_address, scripthash_of

class Client:
    def __init__(self, addr):
        self.s = socket.create_connection(addr, 15)
        self.f = self.s.makefile('rwb')
        self.n = 0
        self.call('server.version', ['electrs-intel', '1.4'])

    def raw(self, method, params):
        rid = self.n
        self.n += 1
        self.f.write((json.dumps({'jsonrpc': '2.0', 'id': rid, 'method': method,
                                  'params': params}) + '\n').encode())
        self.f.flush()
        line = self.f.readline()
        if not line:
            raise IOError('conexion cerrada')
        return json.loads(line)

    def call(self, method, params):
        return self.raw(method, params).get('result')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default='snoop.db')
    ap.add_argument('--server', default='127.0.0.1:50001')
    ap.add_argument('--max-tx', type=int, default=20)
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    host, port = a.server.rsplit(':', 1)
    c = Client((host, int(port)))
    now = int(time.time())
    nb = 0
    for (sh,) in con.execute('select scripthash from scripthashes where resolved_at is null').fetchall():
        r = c.call('blockchain.scripthash.get_balance', [sh]) or {}
        con.execute('update scripthashes set balance_conf=?, balance_unconf=?, resolved_at=? where scripthash=?',
                    (r.get('confirmed'), r.get('unconfirmed'), now, sh))
        nb += 1
    na = 0
    for (sh,) in con.execute('select scripthash from scripthashes where address is null').fetchall():
        hist = c.call('blockchain.scripthash.get_history', [sh]) or []
        for h in hist[:a.max_tx]:
            raw = c.call('blockchain.transaction.get', [h.get('tx_hash'), False])
            if not isinstance(raw, str):
                continue
            for script in tx_output_scripts(raw):
                if scripthash_of(script) == sh:
                    addr = script_to_address(script)
                    if addr:
                        con.execute('update scripthashes set address=? where scripthash=?', (addr, sh))
                        con.execute('''insert or ignore into addresses(address,scripthash,source,first_seen)
                          values(?,?,?,?)''', (addr, sh, 'onchain', now))
                        na += 1
                        break
            else:
                continue
            break
    con.commit()
    c.s.close()
    print('saldos resueltos:', nb, '| direcciones resueltas:', na)

if __name__ == '__main__':
    main()
