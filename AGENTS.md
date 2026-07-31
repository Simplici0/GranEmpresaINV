# AGENTS.md

## Propósito

GranEmpresaINV es una aplicación web interna para gestionar inventario, ventas y cambios de productos. Antes de trazar un plan o modificar el proyecto, leer este archivo y verificar el estado real del código: la mayor parte de la aplicación está concentrada en `main.go` y existen diferencias entre la documentación de despliegue y el workflow de CI.

## Arquitectura

- Aplicación monolítica en Go (`package main`), sin framework HTTP ni separación por capas.
- El punto de entrada es `main.go`; registra un `http.ServeMux`, aplica el middleware de autenticación y escucha en `PORT`.
- La persistencia usa SQLite mediante `modernc.org/sqlite`.
- La autenticación usa hashes `bcrypt` y sesiones almacenadas en SQLite.
- Las vistas son plantillas HTML server-side. No hay frontend separado ni proceso de build para JavaScript/CSS.
- Las plantillas se cargan con rutas relativas, por lo que el binario debe ejecutarse desde un directorio que contenga `templates/` y `static/`.
- `main.go` configura la base de datos, realiza compatibilidad con algunos esquemas legacy, puede sembrar datos demo, registra rutas y arranca el servidor.

## Estructura relevante

- `main.go`: modelos de vista, acceso a datos, esquema/migraciones ad-hoc, autenticación, handlers HTTP y servidor.
- `main_test.go`: pruebas unitarias de FIFO, stock insuficiente y operaciones de reset.
- `templates/`: vistas HTML; `templates/partials/header.html` contiene el layout y estilos compartidos.
- `static/`: favicon y recursos gráficos.
- `deploy/`: servicio systemd, configuración Caddy y script de backup SQLite.
- `.github/workflows/deploy.yml`: compilación y despliegue automatizado.
- `README.md`: guía de despliegue orientada a un servidor Hetzner.
- `data.db` y archivos WAL locales: datos de desarrollo ignorados por Git; no son fixtures ni deben modificarse como parte de un cambio de código.

## Funcionalidades y rutas

- `/login` y `/logout`: inicio y cierre de sesión.
- `/inventario`: consulta de productos y unidades.
- `/inventario/reservar`, `/inventario/dano`, `/inventario/uso-interno` y `/inventario/stock`: operaciones sobre unidades.
- `/productos/new`, `/productos` y `/productos/historial`: creación, consulta y movimientos de productos.
- `/venta/new`, `/venta` y `/venta/confirm`: creación y confirmación de ventas.
- `/cambio/new` y `/cambio`: creación y confirmación de cambios.
- `/dashboard`, `/dashboard/data` y `/csv/ventas`: indicadores y datos de ventas.
- `/productos/csv`, `/csv/template` y `/csv/export`: carga y exportación relacionada con CSV.
- `/admin/users`: administración de usuarios.
- `/admin/settings`: reinicio de usuarios o datos empresariales.
- `/health`: responde `ok` sin validar la conexión con SQLite.

## Base de datos

- `DB_PATH` selecciona la base de datos y por defecto es `data.db`.
- `initDB` crea y ajusta el esquema directamente desde `main.go`; no existe un sistema de migraciones versionadas.
- Las tablas principales son `productos`, `unidades`, `ventas`, `users`, `sessions`, `movimientos` y `app_meta`.
- Los importes se almacenan como `REAL`; conservar la convención existente salvo que el cambio incluya una decisión explícita sobre precisión monetaria.
- SQLite se configura con WAL. Las bases locales pueden tener archivos `.db-wal` y `.db-shm` activos.
- Las migraciones actuales son comprobaciones y `ALTER TABLE` ad-hoc para columnas legacy. Si se cambia el esquema, revisar bases existentes y documentar el camino de actualización.
- `app_meta.demo_seed_disabled` controla el seed demo. Una base nueva puede recibir productos/ventas demo automáticamente; comprobar esta conducta antes de usar una base de producción.
- `cambios` y `precio_venta_historial` aparecen en lógica legacy/reset, pero no forman parte de todo el esquema inicial actual. No asumir que existen en una base recién creada.
- No borrar, recrear ni editar una base SQLite de trabajo para probar código sin confirmar antes la ruta `DB_PATH`.

## Autenticación y permisos

- El middleware global deja públicos `/login`, `/health` y `/static/`; el resto de rutas exige una sesión válida.
- Las sesiones duran 24 horas y se identifican mediante la cookie `session_token`.
- `adminOnly` permite acceso exclusivamente cuando `User.Role == "admin"`.
- La creación automática del administrador usa `ADMIN_USER` y `ADMIN_PASS`; si no están configuradas, no se crea ningún administrador.
- Las operaciones de negocio no deben considerarse administrativas solo porque la UI las oculte: revisar siempre el handler y sus permisos efectivos.
- No hay protección CSRF ni rate limiting. Al añadir formularios o acciones destructivas, considerar explícitamente estas limitaciones.
- La cookie segura se calcula a partir de `r.TLS`; detrás de un reverse proxy TLS puede terminar antes de llegar a Go. Revisar este comportamiento antes de cambiar autenticación o despliegue.

## Convenciones de implementación

- Mantener los cambios pequeños y coherentes con el monolito existente; no introducir un framework o una capa nueva sin necesidad concreta.
- Usar consultas parametrizadas para valores SQL. Los nombres de tabla/columna dinámicos deben validarse antes de interpolarse.
- Las operaciones que modifican stock y ventas deben usar transacciones y preservar la regla FIFO cuando aplique.
- Mantener sincronizados la base de datos y el estado `products` en memoria; después de cambios de catálogo, revisar si es necesario recargar o actualizar el snapshot.
- Para cambios en plantillas, revisar tanto el HTML server-side como el JavaScript inline y los estilos responsive.
- No interpolar valores de usuario, CSV o base de datos en `innerHTML`; preferir `textContent`, creación de nodos o escape explícito.
- Validar en servidor aunque exista validación en el navegador.
- No agregar compatibilidad legacy por anticipación. Si el cambio requiere soportar una base existente, identificar el esquema concreto y añadir una migración verificable.
- No incluir bases SQLite, credenciales, archivos de sesión ni secretos en commits.

## Pruebas y verificación

Ejecutar desde la raíz del repositorio:

```bash
gofmt -d main.go main_test.go
go test ./...
go vet ./...
go build ./...
```

Para cambios sensibles a concurrencia o SQLite, ejecutar también:

```bash
go test -race ./...
```

Para una prueba manual aislada, usar una base temporal y credenciales explícitas:

```bash
DB_PATH=/tmp/granempresa-verification.db \
PORT=18080 \
ADMIN_USER=admin \
ADMIN_PASS='cambiar-esta-clave' \
go run .
```

Luego comprobar `/health` y `/login`. No usar `data.db` para pruebas destructivas.

Si se toca el esquema o el backup, revisar la integridad de una copia con SQLite en modo lectura:

```bash
sqlite3 -readonly /ruta/a/data.db "PRAGMA integrity_check; PRAGMA foreign_key_check;"
```

Las pruebas existentes no cubren todas las rutas HTTP, autenticación, CSV, cambios, migraciones legacy, plantillas ni JavaScript. Los cambios en esas áreas deben incluir pruebas nuevas o una verificación manual documentada.

## Despliegue

- `deploy/systemd/granempresa.service` espera el binario y las plantillas en `/srv/granempresa/app`, con datos en `/srv/granempresa/data/data.db`.
- `deploy/Caddyfile` usa `example.com` como placeholder y hace reverse proxy a `127.0.0.1:8080`.
- `deploy/backup_db.sh` genera copias mediante `VACUUM INTO` y conserva por defecto 14 días (`KEEP_DAYS`).
- `README.md` documenta el servicio `granempresa`, usuario `granempresa` y arquitectura `linux/amd64`.
- `.github/workflows/deploy.yml` actualmente compila `linux/arm64` y despliega con nombres/rutas de `stocki` diferentes a los del README y systemd.
- El workflow reinicia el servicio remoto, pero no ejecuta tests, healthcheck, migraciones, validación de backup ni rollback.
- Antes de modificar despliegue, unificar o confirmar explícitamente el contrato real del servidor; no asumir que README, systemd y CI describen el mismo entorno.
- Antes de una publicación, verificar `go build`, arquitectura del servidor, `DB_PATH`, variables `ADMIN_USER`/`ADMIN_PASS`, permisos de la carpeta de datos y estado del servicio.

## Riesgos conocidos para planificar cambios

- El código de negocio, acceso a datos y handlers está en un archivo de aproximadamente 4.400 líneas; localizar primero las funciones y rutas afectadas antes de proponer una refactorización.
- Los cambios pueden dejar divergencias entre el catálogo en memoria y SQLite si una transacción falla después de actualizar memoria.
- El flujo de cambios y algunas eliminaciones de ventas/productos requieren revisar cuidadosamente la consistencia histórica y el stock, no solo la respuesta HTTP.
- Las exportaciones y consultas grandes no tienen paginación ni límites generales.
- Existen áreas con JavaScript que construyen HTML usando datos de DB o CSV; cualquier modificación de esos flujos debe considerar XSS.
- No hay pruebas de integración de rutas ni de la mayoría de las operaciones de inventario. Una prueba verde no implica cobertura completa.

## Regla para futuros planes

Antes de trazar un plan:

- Leer este `AGENTS.md` y comprobar si el cambio afecta sus supuestos.
- Inspeccionar las rutas, funciones y plantillas concretas en el estado actual del repositorio.
- Identificar si el cambio toca datos persistentes, sesiones, permisos, stock, migraciones o despliegue.
- Definir pruebas automatizadas y, cuando corresponda, una verificación manual con `DB_PATH` temporal.
- Señalar cualquier discrepancia entre `README.md`, `deploy/` y `.github/workflows/deploy.yml` en lugar de ocultarla en el plan.
