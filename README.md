# GranEmpresaINV - Despliegue en producción

Esta guía describe el entorno real de producción verificado el 2026-08-07.
El nombre del artefacto y del servicio en producción es `stocki`, aunque el
módulo Go del proyecto se llama `GranEmpresaINV`.

## Contrato de producción

| Área | Valor real |
| --- | --- |
| Servicio systemd | `stocki.service` |
| Usuario del servicio | `AlvaroC` |
| Ruta de la aplicación | `/opt/stocki` |
| Binario | `/opt/stocki/stocki` |
| Arquitectura | Linux ARM64/AArch64 |
| Puerto interno | `8090` |
| Reverse proxy | Nginx |
| Dominio | `stocki.manosalaia.xyz` |
| Base de datos | `/opt/stocki/data/data.db` |
| Configuración privada | `/opt/stocki/.env` |
| SSH | `AlvaroC@<servidor>`, puerto `2222` |

El workflow de GitHub Actions es el mecanismo de publicación. Los archivos
de `deploy/` son referencias de la infraestructura; el workflow no los copia
ni los instala automáticamente.

## Aplicación

La aplicación es un binario Go monolítico con plantillas server-side. Las
plantillas y los archivos estáticos se cargan mediante rutas relativas, por lo
que el proceso debe ejecutarse con:

```text
WorkingDirectory=/opt/stocki
```

La aplicación usa SQLite en modo WAL. En producción pueden existir junto a la
base los archivos `data.db-wal` y `data.db-shm`.

Al iniciar, `initDB` aplica automáticamente las migraciones pendientes. La
migración 7 agrega el checkout persistente (`checkout_operaciones`,
`checkout_venta_items` y `checkout_cambio_items`) y columnas de trazabilidad en
`ventas`; no requiere pasos manuales, pero debe probarse sobre una copia antes
de publicar una versión nueva.

## Compilación

La arquitectura de producción es ARM64. El binario debe compilarse así:

```bash
GOOS=linux GOARCH=arm64 go build -o stocki .
```

El workflow usa la versión de Go indicada por `go.mod` y ejecuta ese mismo
build para cada publicación desde `main` o mediante ejecución manual.

## Servicio systemd

La unidad activa en el servidor es `/etc/systemd/system/stocki.service`.
La versión de referencia está en `deploy/systemd/stocki.service`:

```ini
[Unit]
Description=Stocki inventory service
After=network.target

[Service]
Type=simple
User=AlvaroC
WorkingDirectory=/opt/stocki
EnvironmentFile=/opt/stocki/.env
ExecStart=/opt/stocki/stocki
Restart=always

[Install]
WantedBy=multi-user.target
```

El workflow no instala ni reemplaza esta unidad. Debe existir previamente en
el servidor. Después de copiar el binario y los recursos, el workflow ejecuta
`sudo systemctl restart stocki`.

## Variables privadas

`/opt/stocki/.env` pertenece a `root:root` y tiene permisos `0600`. No debe
versionarse ni copiarse mediante el workflow.

Su contenido operativo incluye:

```ini
PORT=8090
DB_PATH=/opt/stocki/data/data.db
ADMIN_USER=admin
ADMIN_PASS=<secreto>
```

El código crea el usuario definido por `ADMIN_USER` con rol administrador si
las dos variables existen y ese usuario aún no está en la base. Si el usuario
ya existe, no lo recrea.

## Nginx

Nginx recibe el tráfico público en los puertos 80 y 443 y lo reenvía al
backend Go en `127.0.0.1:8090`. El dominio configurado es:

```text
stocki.manosalaia.xyz
```

La referencia de routing está en `deploy/nginx/stocki.conf`. El archivo del
repositorio es documental y no incluye las rutas privadas de certificados TLS;
la configuración completa y los certificados permanecen en el servidor.

El comportamiento verificado es:

```bash
curl -sS http://127.0.0.1:8090/health
curl -k -sS https://stocki.manosalaia.xyz/health
```

Ambos deben responder `ok`. HTTP público redirige a HTTPS.

## Despliegue automatizado

`.github/workflows/deploy.yml` es el flujo real de producción:

1. Obtiene el código de `main`.
2. Configura la versión de Go de `go.mod`.
3. Compila `stocki` para `linux/arm64`.
4. Se conecta a `37.27.222.238` por SSH en el puerto `2222` como `AlvaroC`.
5. Copia el binario, `templates/` y `static/` a un directorio temporal.
6. Instala el binario en `/opt/stocki/`.
7. Sincroniza `templates/` y `static/` con `--delete`.
8. Reinicia `stocki.service`.

El workflow no modifica `.env`, la base de datos, la unidad systemd ni Nginx.
Esos elementos deben estar configurados y persistir previamente en el VPS.

El workflow actualmente no ejecuta tests, healthcheck, migraciones, validación
de la base, validación del backup ni rollback automático.

## Base de datos

La aplicación usa:

```text
DB_PATH=/opt/stocki/data/data.db
```

La integridad verificada el 2026-08-07 fue `ok` mediante SQLite en modo
solo lectura. Antes de realizar pruebas destructivas, usar siempre una ruta
`DB_PATH` temporal y no la base de producción.

## Backup

El timer activo en producción se llama `stockiapp-backup.timer`, pero su
servicio ejecuta `pg_dump` sobre una base PostgreSQL de otro proyecto. **No
respalda actualmente `/opt/stocki/data/data.db`.**

`deploy/backup_db.sh` es una referencia manual para un futuro backup SQLite;
no está instalado ni ejecutado por el workflow actual. La configuración de
backup de producción se debe tratar como un trabajo separado.

## SSH y puertos

La configuración verificada del servidor usa:

```text
Port 2222
AllowUsers AlvaroC
PermitRootLogin no
```

Los puertos públicos de la aplicación son 80 y 443. El backend escucha en
8090 y no debe confundirse con el puerto SSH 2222.

## Verificación después de un deploy

En el servidor:

```bash
sudo systemctl status stocki.service
sudo journalctl -u stocki.service -n 100 --no-pager
curl -sS http://127.0.0.1:8090/health
curl -k -sS https://stocki.manosalaia.xyz/health
```

El binario debe ser ARM64 y el servicio debe conservar su `WorkingDirectory`,
`EnvironmentFile` y `DB_PATH` de producción.

## Estado del código publicado

Durante la auditoría del 2026-08-07, el binario de producción provenía del
commit `53ef9ad9cc8a053ee9aeecbe1dd699ce1338ea84`, mientras que el checkout
revisado del repositorio estaba en `058f63988911ca401f0d5419bc6058c6664690c2`.
Antes de reemplazar el binario, confirmar que los cambios que existen en
producción ya estén recuperados o integrados en el repositorio.
