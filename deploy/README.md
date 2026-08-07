# Referencias de despliegue

Estos archivos documentan la infraestructura real de producción. No son
consumidos por `.github/workflows/deploy.yml`: el workflow publica el binario,
`templates/` y `static/`, y reinicia el servicio que ya existe en el VPS.

## Archivos activos de referencia

- `systemd/stocki.service`: unidad real de producción.
- `nginx/stocki.conf`: routing de Nginx hacia `127.0.0.1:8090`. Es una
  referencia y no incluye las rutas privadas de certificados TLS.
- `backup_db.sh`: backup SQLite manual de referencia. No es el backup
  programado actualmente en producción.

## Archivos históricos

`legacy/` conserva archivos de una configuración anterior basada en el nombre
`granempresa`, Caddy, el puerto 8080 y las rutas `/srv/granempresa`. No deben
instalarse en el servidor actual.
