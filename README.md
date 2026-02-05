# GranEmpresaINV - Deploy en Hetzner

Esta guía cubre el despliegue en un VPS de Hetzner con Linux (Ubuntu/Debian), usando:
- Binario Go (linux/amd64)
- systemd como servicio
- Caddy como reverse proxy con HTTPS (Let's Encrypt)
- Backup diario de SQLite con rotación

## 1) Requisitos en el servidor

Instala dependencias básicas:

```bash
sudo apt update
sudo apt install -y caddy sqlite3
```

> Si compilas en el servidor, también instala Go (`golang-go`) o usa el instalador oficial de Go.

## 2) Abrir puertos en Hetzner

En el firewall de Hetzner (y/o `ufw` si lo usas), permite:
- 22/tcp (SSH)
- 80/tcp (HTTP) y 443/tcp (HTTPS) para Caddy

Ejemplo con UFW:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 3) Crear usuario y estructura de carpetas

```bash
sudo useradd --system --create-home --home-dir /srv/granempresa --shell /usr/sbin/nologin granempresa
sudo install -d -o granempresa -g granempresa /srv/granempresa/app /srv/granempresa/data /srv/granempresa/backups /srv/granempresa/scripts
```

## 4) Construir el binario (linux/amd64)

### Opción A: compilar en el servidor

```bash
cd /srv/granempresa
sudo -u granempresa git clone <TU_REPO> src
cd /srv/granempresa/src
GOOS=linux GOARCH=amd64 go build -o /srv/granempresa/app/granempresa .
```

Copia las plantillas:

```bash
sudo -u granempresa rsync -a /srv/granempresa/src/templates /srv/granempresa/app/
```

### Opción B: compilar localmente y subir

```bash
GOOS=linux GOARCH=amd64 go build -o granempresa .
rsync -av granempresa templates/ granempresa@<IP>:/srv/granempresa/app/
```

## 5) Configurar systemd

Copia los unit files:

```bash
sudo cp deploy/systemd/granempresa.service /etc/systemd/system/granempresa.service
sudo cp deploy/systemd/granempresa-backup.service /etc/systemd/system/granempresa-backup.service
sudo cp deploy/systemd/granempresa-backup.timer /etc/systemd/system/granempresa-backup.timer
sudo cp deploy/backup_db.sh /srv/granempresa/scripts/backup_db.sh
sudo chown granempresa:granempresa /srv/granempresa/scripts/backup_db.sh
sudo chmod +x /srv/granempresa/scripts/backup_db.sh
```

Recarga systemd y habilita servicios:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now granempresa.service
sudo systemctl enable --now granempresa-backup.timer
```

Verifica estado:

```bash
sudo systemctl status granempresa.service
sudo systemctl list-timers | grep granempresa-backup
```

## 6) Configurar Caddy (HTTPS automático)

Edita `/etc/caddy/Caddyfile` y usa el contenido de `deploy/Caddyfile`:

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo sed -i 's/example.com/TU_DOMINIO/g' /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

> Asegúrate de que el DNS de `TU_DOMINIO` apunte al VPS antes de reiniciar Caddy.

## 7) Base de datos y backups

- La app usa `DB_PATH` (por defecto `data.db`). El servicio la apunta a `/srv/granempresa/data/data.db`.
- El backup diario se ejecuta con `VACUUM INTO` y genera archivos timestamped en `/srv/granempresa/backups`.
- Se conserva la cantidad de días definida por `KEEP_DAYS` (por defecto 14) y se rota automáticamente.

### Ejecutar backup manual

```bash
sudo -u granempresa DB_PATH=/srv/granempresa/data/data.db BACKUP_DIR=/srv/granempresa/backups /srv/granempresa/scripts/backup_db.sh
```

## 8) Ajustes útiles

- Cambiar el puerto interno: edita `Environment=PORT=8080` en `/etc/systemd/system/granempresa.service`.
- Cambiar la ruta de DB: edita `Environment=DB_PATH=/ruta/nueva.db`.
- Ver logs: `journalctl -u granempresa.service -f`
