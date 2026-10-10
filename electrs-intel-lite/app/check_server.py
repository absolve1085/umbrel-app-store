#!/usr/bin/env python3
import argparse, sys
from resolve import Client

PROBES = [
    ('server.version', ['electrs-intel', '1.4']),
    ('blockchain.scripthash.get_balance', ['0' * 64]),
    ('blockchain.scripthash.get_history', ['0' * 64]),
    ('blockchain.scripthash.listunspent', ['0' * 64]),
    ('blockchain.transaction.get', ['0' * 64, False]),
    ('blockchain.block.header', [0]),
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True)
    a = ap.parse_args()
    host, port = a.server.rsplit(':', 1)
    try:
        c = Client((host, int(port)))
    except Exception as e:
        print('conexion: FALLO (%s)' % e)
        sys.exit(1)
    ok = True
    for method, params in PROBES:
        try:
            r = c.raw(method, params)
            err = r.get('error')
            missing = err and 'not found' in str(err.get('message', '')).lower()
            print('%-42s %s' % (method, 'NO SOPORTADO' if missing else 'OK'))
            ok = ok and not missing
        except Exception as e:
            print('%-42s ERROR %s' % (method, e))
            ok = False
    try:
        ver = c.call('server.version', ['electrs-intel', '1.4'])
        if ver:
            print('backend:', ver)
    except Exception:
        pass
    c.s.close()
    sys.exit(0 if ok else 2)

if __name__ == '__main__':
    main()
