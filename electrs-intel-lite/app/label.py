#!/usr/bin/env python3
import sqlite3, argparse

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default='snoop.db')
    ap.add_argument('args', nargs='*', help='add <direccion> <etiqueta> | rm <direccion> | list')
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.execute('create table if not exists labels(address text primary key, label text)')
    if a.args and a.args[0] == 'add' and len(a.args) >= 3:
        con.execute('insert or replace into labels values(?,?)', (a.args[1], ' '.join(a.args[2:])))
        con.commit()
        print('ok')
    elif a.args and a.args[0] == 'rm' and len(a.args) >= 2:
        con.execute('delete from labels where address=?', (a.args[1],))
        con.commit()
        print('ok')
    else:
        for r in con.execute('select address, label from labels order by label'):
            print('%s  %s' % (r[0], r[1]))

if __name__ == '__main__':
    main()
