#!/bin/sh
DB=/data/snoop.db
while true; do
  if [ "$ELECTRUM_SERVER" = "auto" ] || [ -z "$ELECTRUM_SERVER" ]; then
    SERVER=$(python /app/find_server.py 2>/dev/null | head -1)
  else
    SERVER="$ELECTRUM_SERVER"
  fi
  if [ -n "$SERVER" ]; then
    echo "servidor electrum: $SERVER"
    python /app/check_server.py --server "$SERVER" || true
    python /app/parse_pcap.py --db "$DB" /data || true
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
