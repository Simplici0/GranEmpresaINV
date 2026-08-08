# AGENTS.md

## Propósito

GranEmpresaINV es una aplicación web interna para gestionar inventario, ventas y cambios de productos. Antes de trazar un plan o modificar el proyecto, leer este archivo y verificar el estado real del código: la mayor parte de la aplicación está concentrada en `main.go`. El contrato de publicación es `.github/workflows/deploy.yml`; `README.md` y `deploy/` documentan el entorno real.

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
- `main_test.go`: pruebas unitarias de FIFO, conteo de unidades reservadas, stock insuficiente y operaciones de reset.
- `templates/`: vistas HTML; `templates/partials/header.html` contiene el layout y estilos compartidos.
- `static/`: favicon, recursos gráficos y dependencias frontend versionadas localmente (`static/vendor/chart.js/`).
- `deploy/`: referencias del servicio systemd `stocki`, routing Nginx y script manual de backup SQLite.
- `.github/workflows/deploy.yml`: compilación y despliegue automatizado.
- `README.md`: guía de despliegue orientada a un servidor Hetzner.
- `data.db` y archivos WAL locales: datos de desarrollo ignorados por Git; no son fixtures ni deben modificarse como parte de un cambio de código.

## Funcionalidades y rutas

- `/login` y `/logout`: inicio y cierre de sesión.
- `/inventario`: consulta de productos y unidades.
- `/inventario/reservar`, `/inventario/dano` y `/inventario/uso-interno`: operaciones sobre unidades.
- `/inventario/stock`: edición administrativa del producto y ajuste de sus unidades disponibles.
- `/productos/new`, `/productos` y `/productos/historial`: creación, consulta y movimientos de productos.
- `/venta/new`, `/venta` y `/venta/confirm`: creación y confirmación de ventas.
- `/cambio/new` y `/cambio`: creación y confirmación de cambios.
- `/carrito` y `/checkout`: agrupación y confirmación de ventas, cargos y cambios.
- `/dashboard`, `/dashboard/data` y `/csv/ventas`: indicadores y datos de ventas.
- `/productos/csv`, `/csv/template` y `/csv/export`: carga y exportación relacionada con CSV.
- `/admin/users`: administración de usuarios.
- `/admin/settings`: reinicio de usuarios o datos empresariales.
- `/health`: responde `ok` sin validar la conexión con SQLite.

## Base de datos

- `DB_PATH` selecciona la base de datos y por defecto es `data.db`.
- `initDB` crea y ajusta el esquema directamente desde `main.go` mediante migraciones ad-hoc registradas en `schema_migrations`.
- Las tablas principales son `productos`, `unidades`, `ventas`, `users`, `sessions`, `movimientos`, `app_meta` y las tablas `checkout_*` del carrito.
- Los importes se almacenan como `REAL`; conservar la convención existente salvo que el cambio incluya una decisión explícita sobre precisión monetaria.
- SQLite se configura con WAL. Las bases locales pueden tener archivos `.db-wal` y `.db-shm` activos.
- Las migraciones actuales son comprobaciones y `ALTER TABLE` ad-hoc para columnas legacy. Si se cambia el esquema, revisar bases existentes y documentar el camino de actualización.
- `app_meta.demo_seed_disabled` controla el seed demo. Una base nueva puede recibir productos/ventas demo automáticamente; comprobar esta conducta antes de usar una base de producción.
- `cambios` y `precio_venta_historial` aparecen en lógica legacy/reset, pero no forman parte de todo el esquema inicial actual. No asumir que existen en una base recién creada.
- La migración 7 agrega el checkout persistente y columnas de tipo, nombre y referencia en `ventas`; se aplica automáticamente al iniciar y conserva los registros legacy.
- No borrar, recrear ni editar una base SQLite de trabajo para probar código sin confirmar antes la ruta `DB_PATH`.

## Autenticación y permisos

- El middleware global deja públicos `/login`, `/health` y `/static/`; el resto de rutas exige una sesión válida.
- Las sesiones duran 24 horas y se identifican mediante la cookie `session_token`.
- `adminOnly` permite acceso exclusivamente cuando `User.Role == "admin"`.
- `/inventario/stock` está protegido server-side para administradores; la UI tampoco muestra "Editar producto" a empleados.
- La creación automática del administrador usa `ADMIN_USER` y `ADMIN_PASS`; si no están configuradas, no se crea ningún administrador.
- Las operaciones de negocio no deben considerarse administrativas solo porque la UI las oculte: revisar siempre el handler y sus permisos efectivos.
- No hay protección CSRF ni rate limiting. Al añadir formularios o acciones destructivas, considerar explícitamente estas limitaciones.
- La cookie segura se calcula a partir de `r.TLS`; detrás de un reverse proxy TLS puede terminar antes de llegar a Go. Revisar este comportamiento antes de cambiar autenticación o despliegue.

## Comportamiento actual de la interfaz

- Inventario transporta y muestra por separado las unidades disponibles y reservadas. El filtro inicial sigue siendo `Disponible`; el filtro `Reservado` incluye productos con reservas aunque también tengan unidades disponibles.
- Las unidades reservadas no cuentan como disponibles para vender ni para ajustar la cantidad disponible.
- Un cambio confirmado elimina las unidades salientes disponibles, crea las entrantes como unidades `Disponible` y registra ambos movimientos; no borrar unidades históricas ya existentes en estado `Cambio`.
- Los cambios rápidos registran una operación estructurada en `cambio_operaciones`; los cambios agrupados del carrito usan `checkout_operaciones` y `checkout_cambio_items` para conservar listas generales de salidas/entradas. No reconstruir cambios antiguos desde `movimientos`.
- El alta exitosa en `/productos` usa POST-Redirect-GET hacia `/productos/new`, muestra un mensaje de confirmación y deja el formulario limpio con el siguiente SKU. Los errores conservan los valores introducidos.
- La acción administrativa del inventario se llama `Editar producto` y permite modificar cantidad disponible, nombre, línea y precio de venta. El SKU no se modifica y las unidades reservadas quedan intactas.
- El login incluye un control `Mostrar/Ocultar` para la contraseña, oculta por defecto y sin alterar el flujo de autenticación.
- Los filtros del inventario aparecen en el orden Búsqueda, Estado, Línea y Caducidad. Búsqueda tiene mayor peso visual en escritorio y los breakpoints responsive se mantienen.
- La paginación marca visualmente el número activo y lo expone mediante `aria-current="page"`.
- El dashboard usa Chart.js local para la línea temporal de ventas y la dona por método de pago. El KPI, la leyenda, los conteos por estado y la tabla permanecen como HTML accesible.
- Las gráficas del dashboard se actualizan sin recarga al cambiar el rango, cancelan peticiones anteriores y muestran estados de carga o error.

## Convenciones de implementación

- Mantener los cambios pequeños y coherentes con el monolito existente; no introducir un framework o una capa nueva sin necesidad concreta.
- Usar consultas parametrizadas para valores SQL. Los nombres de tabla/columna dinámicos deben validarse antes de interpolarse.
- Las operaciones que modifican stock y ventas deben usar transacciones y preservar la regla FIFO cuando aplique.
- En la edición de producto, `cantidad` significa objetivo de unidades disponibles; no convertirla en stock total sin revisar primero el tratamiento de reservas.
- Mantener sincronizados la base de datos y el estado `products` en memoria; después de cambios de catálogo, revisar si es necesario recargar o actualizar el snapshot.
- Para cambios en plantillas, revisar tanto el HTML server-side como el JavaScript inline y los estilos responsive.
- Las librerías frontend de terceros deben fijarse a una versión exacta, servirse desde `static/vendor/` y conservar su licencia/procedencia.
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

- Producción usa `stocki.service`, usuario `AlvaroC`, `WorkingDirectory=/opt/stocki`, binario `/opt/stocki/stocki` y `EnvironmentFile=/opt/stocki/.env`.
- El servicio escucha en `PORT=8090` y usa `DB_PATH=/opt/stocki/data/data.db`.
- La arquitectura de producción es Linux ARM64/AArch64.
- Nginx atiende `stocki.manosalaia.xyz` en 80/443 y hace proxy a `127.0.0.1:8090`; la referencia está en `deploy/nginx/stocki.conf`.
- `.github/workflows/deploy.yml` compila para ARM64, conecta por SSH al puerto 2222 como `AlvaroC`, sincroniza el binario, `templates/` y `static/` en `/opt/stocki` y reinicia `stocki`.
- El workflow no copia `.env`, no instala systemd ni Nginx y no ejecuta tests, healthcheck, migraciones, validación de backup ni rollback.
- `deploy/backup_db.sh` es un backup SQLite manual de referencia; el backup programado existente en producción respalda otra base PostgreSQL y no la SQLite de esta aplicación.
- Los archivos históricos que describían `/srv/granempresa`, Caddy y el puerto 8080 están en `deploy/legacy/` y no forman parte del contrato activo.
- Antes de una publicación, verificar `go build`, arquitectura del servidor, `DB_PATH`, variables `ADMIN_USER`/`ADMIN_PASS`, permisos de la carpeta de datos y estado de `stocki.service`.

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
