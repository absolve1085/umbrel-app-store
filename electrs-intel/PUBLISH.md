# Publicar en los stores de Umbrel

La carpeta `umbrel-app/` es el repo de la app (renombrar a `electrs-intel/`).
El contenido de `app/` debe estar sincronizado con la raiz del proyecto:

```bash
cp parse_pcap.py resolve.py harvest.py analyze.py geo.py dashboard.py \
   label.py check_server.py find_server.py umbrel-app/app/
```

## Store semillabitcoin

```bash
gh auth switch -u semillabitcoin
cd ~/projects/umbrel-app-store
cp -r ~/projects/electrs-snoop/umbrel-app electrs-intel
# bump de version en electrs-intel/umbrel-app.yml si aplica
git add electrs-intel && git commit -m "electrs-intel vX.Y.Z" && git push
```

El campo `icon` del manifest apunta a
`https://github.com/semillabitcoin/umbrel-app-store/raw/master/electrs-intel/icon.png`
(icon.png ya va incluido en la carpeta).

## Store 4rkad

```bash
gh auth switch -u 4rkad
cd ~/claude/proyectos/4rkad-umbrel-app-store
cp -r ~/projects/electrs-snoop/umbrel-app electrs-intel
# actualizar el icon: del manifest al raw de 4rkad/umbrel-app-store
git add electrs-intel && git commit -m "electrs-intel vX.Y.Z" && git push
```

## Checklist de version

- [ ] bump `version:` en `umbrel-app.yml` y `image:` del sniffer en compose
- [ ] `cp` de los .py a `app/`
- [ ] `python3 -m py_compile app/*.py`
- [ ] verificar que el icon raw resuelve (200) tras el push
- [ ] probar en un Umbrel: install -> ver logs de `monitor` (autodescubrimiento
      + `check_server` debe dar todo OK en electrs/ElectrumX/Fulcrum)
- [ ] configurar `APP_PASSWORD` en el env del compose si se expone via Tor

## Requisitos de la app

- Un servidor Electrum en la misma máquina (electrs, ElectrumX o Fulcrum) con
  su puerto RPC en claro accesible (50001 por defecto; configurable con
  `ELECTRUM_PORT`). Autodescubrimiento via docker.sock o `ELECTRUM_SERVER`.
- El sniffer usa `network_mode: host` + NET_RAW/NET_ADMIN: es imprescindible
  para ver el trafico inter-contenedores (incluido el que termina en el
  hidden service de Tor) sin depender de nombres de contenedor.
