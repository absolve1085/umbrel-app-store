#!/bin/sh
DB=/data/snoop.db
EXCL=$(python - <<'EOF'
import socket
ips = []
try:
    ips.append(socket.gethostbyname(socket.gethostname()))
except Exception:
    pass
try:
    for l in open('/proc/net/route').read().splitlines()[1:]:
        f = l.split()
        if f[1] == '00000000':
            ips.append('.'.join(str(int(f[2][i:i+2],16)) for i in (6,4,2,0)))
            break
except Exception:
    pass
print(','.join(ips))
EOF
)
export EXCLUDE_IPS="$EXCL"
echo "IPs propias excluidas: ${EXCL:-ninguna}"
python /app/ensure_sniffer.py || echo "aviso: no pude desplegar el sniffer (docker.sock)"
while true; do
  if [ "$ELECTRUM_SERVER" = "auto" ] || [ -z "$ELECTRUM_SERVER" ]; then
    SERVER=$(python /app/find_server.py 2>/dev/null | head -1)
  else
    SERVER="$ELECTRUM_SERVER"
  fi
  if [ -n "$SERVER" ]; then
    echo "servidor electrum: $SERVER"
    python /app/check_server.py --server "$SERVER" || true
    python /app/parse_pcap.py --db "$DB" --exclude "$EXCL" --prune /data || true
    python /app/resolve.py --db "$DB" --server "$SERVER" || true
    python /app/harvest.py --db "$DB" --server "$SERVER" || true
    python /app/geo.py --db "$DB" || true
    python /app/analyze.py --db "$DB" --server "$SERVER" || true
    python - "$DB" <<'EOF'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
for ts, kind, detail in con.execute('select ts, kind, detail from alerts where seen=0 order by ts'):
    print('ALERTA [%s] %s' % (kind, detail))
EOF
  else
    echo "no encuentro servidor electrum: fija ELECTRUM_SERVER=host:port"
  fi
  sleep 60
done
