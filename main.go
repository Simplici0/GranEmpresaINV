package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

type inventoryPageData struct {
	Title       string
	Subtitle    string
	RoutePrefix string
	Flash       string
	Products    []inventoryProduct
	CurrentUser *User
}

type unitOption struct {
	ID string
}

type productOption struct {
	ID    string
	Name  string
	Line  string
	Units []unitOption
}

type csvFailedRow struct {
	Row   int    `json:"row"`
	SKU   string `json:"sku"`
	Error string `json:"error"`
}

type csvUploadResponse struct {
	CreatedProducts int            `json:"created_products"`
	UpdatedProducts int            `json:"updated_products"`
	CreatedUnits    int            `json:"created_units"`
	FailedRows      []csvFailedRow `json:"failed_rows"`
}

type inventoryUnit struct {
	ID          string
	Estado      string
	EstadoClass string
	CreadoEn    string
	Caducidad   string
	FIFO        string
}

type inventoryProduct struct {
	ID           string
	Name         string
	Line         string
	EstadoLabel  string
	EstadoClass  string
	Disponible   int
	Unidades     []inventoryUnit
	DisabledSale bool
}

var errInsufficientStock = fmt.Errorf("stock insuficiente")

type sqlExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func upsertProducto(exec sqlExecer, sku, nombre, linea, now string) error {
	// productos table is part of the existing DB schema and uses sku as the primary key.
	// Other columns (prices, discount, notes) have defaults so manual creation can omit them.
	_ = now // kept for backwards-compat in case we later add created_at.
	_, err := exec.Exec(`
		INSERT INTO productos (sku, id, linea, nombre)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(sku) DO UPDATE SET
			id = excluded.id,
			linea = excluded.linea,
			nombre = excluded.nombre
	`, sku, sku, linea, nombre)
	return err
}

func seedProductosIfMissing(db *sql.DB, defaults []productOption) error {
	// Backfill unknown products that already exist in inventory units.
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO productos (sku, id, nombre, linea)
		SELECT DISTINCT producto_id, producto_id, producto_id, 'Sin línea'
		FROM unidades
	`); err != nil {
		return err
	}

	for _, p := range defaults {
		if _, err := db.Exec(`
			INSERT OR IGNORE INTO productos (sku, id, nombre, linea)
			VALUES (?, ?, ?, ?)
		`, p.ID, p.ID, p.Name, p.Line); err != nil {
			return err
		}
	}
	return nil
}

func loadProductos(db *sql.DB) ([]productOption, error) {
	rows, err := db.Query(`SELECT sku, nombre, linea FROM productos ORDER BY sku`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	products := []productOption{}
	for rows.Next() {
		var p productOption
		if err := rows.Scan(&p.ID, &p.Name, &p.Line); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return products, nil
}

type cambioFormData struct {
	Title               string
	Subtitle            string
	ProductoID          string
	Productos           []productOption
	Unidades            []unitOption
	PersonaCambio       string
	Notas               string
	Salientes           []string
	SalientesMap        map[string]bool
	IncomingMode        string
	IncomingExistingID  string
	IncomingExistingQty int
	IncomingNewSKU      string
	IncomingNewName     string
	IncomingNewLine     string
	IncomingNewQty      int
	Errors              map[string]string
	CurrentUser         *User
}

type cambioConfirmData struct {
	Title               string
	Subtitle            string
	ProductoID          string
	ProductoNombre      string
	PersonaCambio       string
	Notas               string
	Salientes           []string
	Entrantes           []string
	IncomingMode        string
	IncomingExistingID  string
	IncomingExistingQty int
	IncomingNewSKU      string
	IncomingNewName     string
	IncomingNewLine     string
	IncomingNewQty      int
	CurrentUser         *User
}

type estadoCount struct {
	Estado   string
	Cantidad int
	Link     string
}

type periodTotal struct {
	Label   string
	Total   string
	Range   string
	Value   float64
	Percent float64
}

type metodoPagoTotal struct {
	Metodo   string
	Cantidad int
	Total    string
	Value    float64
}

type timelinePoint struct {
	Fecha    string
	Cantidad int
	Total    string
	Value    float64
	Index    int
	Percent  float64
}

type pieSlice struct {
	Metodo  string
	Total   string
	Percent float64
	Offset  float64
	Gap     float64
	Color   string
}

type dashboardData struct {
	Title           string
	Subtitle        string
	EstadoConteos   []estadoCount
	MetodosPago     []metodoPagoTotal
	PieSlices       []pieSlice
	PieTotal        string
	MaxTimeline     float64
	MaxTimelineText string
	TimelinePoints  string
	Timeline        []timelinePoint
	CurrentUser     *User
	RangeStart      string
	RangeEnd        string
	RangeTotal      string
	RangeCount      int
}

type User struct {
	ID       int
	Username string
	Role     string
	IsActive bool
}

type contextKey string

const userContextKey contextKey = "user"

func findProduct(products []productOption, id string) (productOption, bool) {
	for _, product := range products {
		if product.ID == id {
			return product, true
		}
	}
	return productOption{}, false
}

func buildEntranteIDs(prefix string, qty int) []string {
	ids := make([]string, 0, qty)
	for i := 1; i <= qty; i++ {
		ids = append(ids, prefix+"-"+strconv.Itoa(i))
	}
	return ids
}

func buildSalientesMap(salientes []string) map[string]bool {
	mapped := make(map[string]bool, len(salientes))
	for _, id := range salientes {
		mapped[id] = true
	}
	return mapped
}

func estadoClass(estado string) string {
	switch estado {
	case "Disponible", "available":
		return "available"
	case "Reservada", "Reservado", "reserved":
		return "reserved"
	case "Danada", "Dañada", "Dañado", "damaged":
		return "damaged"
	case "Vendida", "Vendido", "sold":
		return "sold"
	case "Cambio", "swapped":
		return "swapped"
	default:
		return "available"
	}
}

func ensureMovimientosTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS movimientos (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			producto_id TEXT NOT NULL,
			unidad_id TEXT NOT NULL,
			tipo TEXT NOT NULL,
			nota TEXT NOT NULL DEFAULT '',
			usuario TEXT NOT NULL DEFAULT '',
			fecha TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_movimientos_producto_fecha ON movimientos (producto_id, fecha);
		CREATE INDEX IF NOT EXISTS idx_movimientos_unidad_fecha ON movimientos (unidad_id, fecha);
	`)
	return err
}

func logMovimientos(tx *sql.Tx, productoID string, unidadIDs []string, tipo, nota string, user *User, now string) error {
	username := ""
	if user != nil {
		username = user.Username
	}
	stmt, err := tx.Prepare(`INSERT INTO movimientos (producto_id, unidad_id, tipo, nota, usuario, fecha) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, unidadID := range unidadIDs {
		if _, err := stmt.Exec(productoID, unidadID, tipo, nota, username, now); err != nil {
			return err
		}
	}
	return nil
}

func selectAndMarkUnitsSold(tx *sql.Tx, productID string, qty int) ([]string, error) {
	return selectAndMarkUnitsByStatus(tx, productID, qty, "Vendida")
}

func selectAndMarkUnitsByStatus(tx *sql.Tx, productID string, qty int, nextStatus string) ([]string, error) {
	if qty <= 0 {
		return nil, fmt.Errorf("cantidad inválida")
	}

	rows, err := tx.Query(`
		SELECT id
		FROM unidades
		WHERE producto_id = ? AND estado IN ('Disponible', 'available')
		ORDER BY creado_en, id
		LIMIT ?`, productID, qty)
	if err != nil {
		return nil, fmt.Errorf("query unidades: %w", err)
	}
	defer rows.Close()

	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan unidad: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows unidades: %w", err)
	}

	if len(ids) < qty {
		return nil, errInsufficientStock
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, 0, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}

	query := fmt.Sprintf("UPDATE unidades SET estado = ? WHERE id IN (%s) AND estado IN ('Disponible', 'available')", strings.Join(placeholders, ","))
	updateArgs := make([]interface{}, 0, len(args)+1)
	updateArgs = append(updateArgs, nextStatus)
	updateArgs = append(updateArgs, args...)
	result, err := tx.Exec(query, updateArgs...)
	if err != nil {
		return nil, fmt.Errorf("update unidades: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("rows affected: %w", err)
	}
	if int(affected) != qty {
		return nil, fmt.Errorf("unidades actualizadas inesperadas: %d", affected)
	}

	return ids, nil
}

func availableUnitsByProduct(db *sql.DB, productID string) ([]unitOption, error) {
	rows, err := db.Query(`
		SELECT id
		FROM unidades
		WHERE producto_id = ? AND estado IN ('Disponible', 'available')
		ORDER BY creado_en, id`, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	units := []unitOption{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		units = append(units, unitOption{ID: id})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return units, nil
}

func formatCurrency(value float64) string {
	return fmt.Sprintf("$%.0f", value)
}

func parseDateOrDefault(value string, fallback time.Time) time.Time {
	if value == "" {
		return fallback
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return fallback
	}
	return parsed
}

func statusLabel(estado string) string {
	labels := map[string]string{
		"available":  "Disponible",
		"sold":       "Vendido",
		"swapped":    "Cambio",
		"Disponible": "Disponible",
		"Vendida":    "Vendido",
		"Vendido":    "Vendido",
		"Cambio":     "Cambio",
	}
	if label, ok := labels[estado]; ok {
		return label
	}
	return estado
}

func buildTimelinePoints(timeline []timelinePoint, width, height, padding float64) string {
	if len(timeline) == 0 {
		return ""
	}
	if len(timeline) == 1 {
		x := padding
		y := height - padding - (timeline[0].Percent/100)*(height-2*padding)
		return fmt.Sprintf("%.1f,%.1f", x, y)
	}
	step := (width - 2*padding) / float64(len(timeline)-1)
	points := make([]string, 0, len(timeline))
	for i, point := range timeline {
		x := padding + step*float64(i)
		y := height - padding - (point.Percent/100)*(height-2*padding)
		points = append(points, fmt.Sprintf("%.1f,%.1f", x, y))
	}
	return strings.Join(points, " ")
}

func generateToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

func setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		Expires:  expiresAt,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func userFromContext(r *http.Request) *User {
	if user, ok := r.Context().Value(userContextKey).(*User); ok {
		return user
	}
	return nil
}

func userFromRequest(db *sql.DB, r *http.Request) (*User, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil, err
	}

	var (
		user       User
		isActive   int
		expiresRaw string
	)
	query := `
		SELECT u.id, u.username, u.role, u.is_active, s.expires_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token = ?`
	if err := db.QueryRow(query, cookie.Value).Scan(&user.ID, &user.Username, &user.Role, &isActive, &expiresRaw); err != nil {
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		return nil, err
	}
	if time.Now().After(expiresAt) {
		_, _ = db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
		return nil, sql.ErrNoRows
	}
	user.IsActive = isActive == 1
	if !user.IsActive {
		_, _ = db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
		return nil, sql.ErrNoRows
	}
	return &user, nil
}

func authMiddleware(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow unauthenticated access to healthcheck and static assets.
		// Static assets are safe to serve publicly and needed for the login page too.
		if r.URL.Path == "/login" || r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		user, err := userFromRequest(db, r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := userFromContext(r)
		if user == nil || user.Role != "admin" {
			http.Error(w, "Acceso restringido a administradores.", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func initDB(path string, paymentMethods []string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}
	// Keep FK enforcement disabled during migrations/seeding to avoid startup failures
	// on legacy schemas; re-enable once we've aligned the schema.
	if _, err := db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS productos (
		sku TEXT PRIMARY KEY,
		id TEXT,
		linea TEXT NOT NULL,
		nombre TEXT NOT NULL,
		precio_base REAL NOT NULL DEFAULT 0,
		precio_venta REAL NOT NULL DEFAULT 0,
		precio_consultora REAL NOT NULL DEFAULT 0,
		descuento REAL NOT NULL DEFAULT 0,
		anotaciones TEXT NOT NULL DEFAULT '',
		aplica_caducidad INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_productos_linea ON productos (linea);

	CREATE TABLE IF NOT EXISTS ventas (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		producto_id TEXT NOT NULL,
		cantidad INTEGER NOT NULL,
		precio_final REAL NOT NULL,
		metodo_pago TEXT NOT NULL,
		notas TEXT NOT NULL DEFAULT '',
		fecha TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ventas_fecha ON ventas (fecha);
	CREATE INDEX IF NOT EXISTS idx_ventas_metodo ON ventas (metodo_pago);

	CREATE TABLE IF NOT EXISTS unidades (
		id TEXT PRIMARY KEY,
		producto_id TEXT NOT NULL,
		estado TEXT NOT NULL,
		creado_en TEXT NOT NULL,
		caducidad TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_unidades_estado ON unidades (estado);

	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL CHECK (role IN ('admin', 'empleado')),
		created_at TEXT NOT NULL,
		is_active INTEGER NOT NULL DEFAULT 1
	);
	CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);
	`

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	if err := ensureMovimientosTable(db); err != nil {
		return nil, err
	}

	// Legacy DB fix: precio_venta_historial has FK REFERENCES productos(id),
	// but older productos tables may not have the "id" column.
	var productosHasID int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('productos') WHERE name = 'id'").Scan(&productosHasID); err != nil {
		return nil, err
	}
	if productosHasID == 0 {
		if _, err := db.Exec("ALTER TABLE productos ADD COLUMN id TEXT"); err != nil {
			return nil, err
		}
	}
	// Backfill id for existing rows and ensure uniqueness so FKs can reference it.
	if _, err := db.Exec("UPDATE productos SET id = sku WHERE id IS NULL OR id = ''"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_productos_id_unique ON productos(id)"); err != nil {
		return nil, err
	}

	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, err
	}

	var notasColumn string
	if err := db.QueryRow("SELECT name FROM pragma_table_info('ventas') WHERE name = 'notas'").Scan(&notasColumn); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if notasColumn == "" {
		if _, err := db.Exec("ALTER TABLE ventas ADD COLUMN notas TEXT NOT NULL DEFAULT ''"); err != nil {
			return nil, err
		}
	}

	var caducidadColumn string
	if err := db.QueryRow("SELECT name FROM pragma_table_info('unidades') WHERE name = 'caducidad'").Scan(&caducidadColumn); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if caducidadColumn == "" {
		if _, err := db.Exec("ALTER TABLE unidades ADD COLUMN caducidad TEXT"); err != nil {
			return nil, err
		}
	}

	var ventasCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM ventas").Scan(&ventasCount); err != nil {
		return nil, err
	}

	if ventasCount == 0 {
		if err := seedVentas(db, paymentMethods); err != nil {
			return nil, err
		}
	}

	var unidadesCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM unidades").Scan(&unidadesCount); err != nil {
		return nil, err
	}

	if unidadesCount == 0 {
		if err := seedUnidades(db); err != nil {
			return nil, err
		}
	}

	if err := seedAdminUser(db); err != nil {
		return nil, err
	}

	return db, nil
}

func seedVentas(db *sql.DB, paymentMethods []string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("prepare ventas: %w (rollback: %v)", err, rollbackErr)
		}
		return err
	}
	defer stmt.Close()

	baseDate := time.Now()
	products := []string{"P-001", "P-002", "P-003"}
	for i := 0; i < 14; i++ {
		date := baseDate.AddDate(0, 0, -i).Format("2006-01-02")
		entries := (i % 3) + 2
		for j := 0; j < entries; j++ {
			productoID := products[(i+j)%len(products)]
			cantidad := (j % 3) + 1
			precio := float64(18000 + (i * 1200) + (j * 800))
			metodo := paymentMethods[(i+j)%len(paymentMethods)]
			if _, err := stmt.Exec(productoID, cantidad, precio, metodo, "Venta seed", date); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					return fmt.Errorf("insert ventas: %w (rollback: %v)", err, rollbackErr)
				}
				return err
			}
		}
	}

	return tx.Commit()
}

func seedUnidades(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("prepare unidades: %w (rollback: %v)", err, rollbackErr)
		}
		return err
	}
	defer stmt.Close()

	statuses := []string{"Disponible", "Vendida", "Cambio"}
	products := []string{"P-001", "P-002", "P-003"}
	now := time.Now()
	for i := 1; i <= 36; i++ {
		id := fmt.Sprintf("U-%03d", i)
		productoID := products[i%len(products)]
		estado := statuses[i%len(statuses)]
		createdAt := now.AddDate(0, 0, -i).Format(time.RFC3339)
		expiryAt := now.AddDate(0, 0, 20+i).Format("2006-01-02")
		if _, err := stmt.Exec(id, productoID, estado, createdAt, expiryAt); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return fmt.Errorf("insert unidades: %w (rollback: %v)", err, rollbackErr)
			}
			return err
		}
	}

	return tx.Commit()
}

func seedAdminUser(db *sql.DB) error {
	adminUser := os.Getenv("ADMIN_USER")
	adminPass := os.Getenv("ADMIN_PASS")
	if adminUser == "" || adminPass == "" {
		log.Print("ADMIN_USER/ADMIN_PASS no configurados, omitiendo creación automática de admin.")
		return nil
	}

	var existingID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", adminUser).Scan(&existingID)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		INSERT INTO users (username, password_hash, role, created_at, is_active)
		VALUES (?, ?, 'admin', ?, 1)
	`, adminUser, string(hashed), time.Now().Format(time.RFC3339))
	return err
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "data.db"
	}

	tmpl := template.Must(template.ParseFiles(
		"templates/admin_users.html",
		"templates/dashboard.html",
		"templates/inventario.html",
		"templates/login.html",
		"templates/product_new.html",
		"templates/venta_new.html",
		"templates/venta_confirm.html",
		"templates/cambio_new.html",
		"templates/cambio_confirm.html",
		"templates/csv_template.html",
		"templates/csv_export.html",
		"templates/partials/header.html",
	))

	paymentMethods := []string{"Efectivo", "Transferencia", "Tarjeta", "Nequi", "Daviplata", "Bre-B"}

	db, err := initDB(dbPath, paymentMethods)
	if err != nil {
		log.Fatalf("Error al abrir SQLite: %v", err)
	}
	defer db.Close()

	// Diagnostics to confirm which DB is being used at runtime (helps debug login issues).
	if wd, err := os.Getwd(); err == nil {
		if abs, err := filepath.Abs(dbPath); err == nil {
			log.Printf("DB_PATH=%s (abs=%s) cwd=%s", dbPath, abs, wd)
		} else {
			log.Printf("DB_PATH=%s cwd=%s", dbPath, wd)
		}
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(new(int)); err != nil {
		log.Printf("DB users table not queryable: %v", err)
	} else {
		var totalUsers int
		if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers); err == nil {
			log.Printf("Users total=%d", totalUsers)
		}
		var adminMatches int
		if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&adminMatches); err == nil {
			log.Printf("Users username=admin matches=%d", adminMatches)
		} else {
			log.Printf("Users username=admin query failed: %v", err)
		}
	}

	var productsMu sync.RWMutex
	defaultProducts := []productOption{
		{
			ID:   "P-001",
			Name: "Proteína Balance 500g",
			Line: "Nutrición",
		},
		{
			ID:   "P-002",
			Name: "Crema Regeneradora",
			Line: "Dermocosmética",
		},
		{
			ID:   "P-003",
			Name: "Leche Pediátrica Premium",
			Line: "Pediatría",
		},
	}
	if err := seedProductosIfMissing(db, defaultProducts); err != nil {
		log.Fatalf("Error al seed de productos: %v", err)
	}
	products, err := loadProductos(db)
	if err != nil {
		log.Fatalf("Error al cargar productos: %v", err)
	}

	type ventaFormData struct {
		Title       string
		Subtitle    string
		ProductoID  string
		Cantidad    int
		PrecioFinal string
		MetodoPago  string
		Notas       string
		Errors      map[string]string
		MetodoPagos []string
		RoutePrefix string
		CurrentUser *User
	}

	type ventaConfirmData struct {
		Title       string
		Subtitle    string
		ProductoID  string
		Cantidad    int
		PrecioFinal string
		MetodoPago  string
		Notas       string
		CurrentUser *User
	}

	type loginPageData struct {
		Title    string
		Error    string
		Username string
	}

	type adminUserRow struct {
		ID        int
		Username  string
		Role      string
		IsActive  bool
		CreatedAt string
	}

	type adminUsersData struct {
		Title       string
		Subtitle    string
		Users       []adminUserRow
		CurrentUser *User
	}

	type productNewData struct {
		Title       string
		Subtitle    string
		SKU         string
		Nombre      string
		Linea       string
		Cantidad    int
		AplicaCad   bool
		Caducidad   string
		Errors      map[string]string
		CurrentUser *User
	}

	mux := http.NewServeMux()

	// Serve static assets from ./static at /static/.
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if user, err := userFromRequest(db, r); err == nil && user != nil {
				http.Redirect(w, r, "/inventario", http.StatusSeeOther)
				return
			}
			data := loginPageData{
				Title: "Iniciar sesión",
			}
			if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
				http.Error(w, "Error al renderizar login", http.StatusInternalServerError)
			}
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		var (
			user     User
			hash     string
			isActive int
		)
		err := db.QueryRow(`
					SELECT id, username, password_hash, role, is_active
					FROM users
					WHERE username = ?
				`, username).Scan(&user.ID, &user.Username, &hash, &user.Role, &isActive)
		if err != nil || isActive != 1 {
			if err != nil {
				log.Printf("login: lookup failed username=%q err=%v", username, err)
			} else {
				log.Printf("login: user inactive username=%q", username)
			}
			data := loginPageData{
				Title:    "Iniciar sesión",
				Error:    "Credenciales inválidas.",
				Username: username,
			}
			w.WriteHeader(http.StatusUnauthorized)
			if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
				http.Error(w, "Error al renderizar login", http.StatusInternalServerError)
			}
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
			log.Printf("login: password mismatch username=%q", username)
			data := loginPageData{
				Title:    "Iniciar sesión",
				Error:    "Credenciales inválidas.",
				Username: username,
			}
			w.WriteHeader(http.StatusUnauthorized)
			if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
				http.Error(w, "Error al renderizar login", http.StatusInternalServerError)
			}
			return
		}

		token, err := generateToken()
		if err != nil {
			http.Error(w, "No se pudo generar sesión", http.StatusInternalServerError)
			return
		}
		expiresAt := time.Now().Add(24 * time.Hour)
		_, err = db.Exec(`
			INSERT INTO sessions (token, user_id, created_at, expires_at)
			VALUES (?, ?, ?, ?)
		`, token, user.ID, time.Now().Format(time.RFC3339), expiresAt.Format(time.RFC3339))
		if err != nil {
			http.Error(w, "No se pudo guardar la sesión", http.StatusInternalServerError)
			return
		}

		setSessionCookie(w, token, expiresAt, r.TLS != nil)
		http.Redirect(w, r, "/inventario", http.StatusSeeOther)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
			return
		}
		if cookie, err := r.Cookie("session_token"); err == nil {
			_, _ = db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
		}
		clearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	mux.HandleFunc("/admin/users", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`SELECT id, username, role, is_active, created_at FROM users ORDER BY id`)
		if err != nil {
			http.Error(w, "Error al consultar usuarios", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		users := []adminUserRow{}
		for rows.Next() {
			var user adminUserRow
			var isActive int
			if err := rows.Scan(&user.ID, &user.Username, &user.Role, &isActive, &user.CreatedAt); err != nil {
				http.Error(w, "Error al leer usuarios", http.StatusInternalServerError)
				return
			}
			user.IsActive = isActive == 1
			users = append(users, user)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "Error al procesar usuarios", http.StatusInternalServerError)
			return
		}

		data := adminUsersData{
			Title:       "Gestión de usuarios",
			Subtitle:    "Control de accesos y roles del inventario.",
			Users:       users,
			CurrentUser: userFromContext(r),
		}
		if err := tmpl.ExecuteTemplate(w, "admin_users.html", data); err != nil {
			http.Error(w, "Error al renderizar usuarios", http.StatusInternalServerError)
		}
	}))

	mux.HandleFunc("/productos/new", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		data := productNewData{
			Title:       "Crear producto",
			Subtitle:    "Acción reservada para administradores.",
			Cantidad:    1,
			CurrentUser: userFromContext(r),
		}
		if err := tmpl.ExecuteTemplate(w, "product_new.html", data); err != nil {
			http.Error(w, "Error al renderizar productos", http.StatusInternalServerError)
		}
	}))

	mux.HandleFunc("/productos", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/productos/new", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
			return
		}

		sku := strings.TrimSpace(r.FormValue("sku"))
		nombre := strings.TrimSpace(r.FormValue("nombre"))
		linea := strings.TrimSpace(r.FormValue("linea"))
		cantidadRaw := strings.TrimSpace(r.FormValue("cantidad"))
		aplicaCad := r.FormValue("aplica_caducidad") != ""
		caducidad := strings.TrimSpace(r.FormValue("fecha_caducidad"))

		errors := map[string]string{}
		if sku == "" {
			errors["sku"] = "SKU obligatorio."
		}
		if nombre == "" {
			errors["nombre"] = "Nombre obligatorio."
		}
		if linea == "" {
			errors["linea"] = "Línea obligatoria."
		}
		cantidad, err := strconv.Atoi(cantidadRaw)
		if err != nil || cantidad <= 0 {
			errors["cantidad"] = "Cantidad debe ser entero mayor a 0."
		}
		if aplicaCad {
			if caducidad == "" {
				errors["fecha_caducidad"] = "Fecha caducidad requerida si aplica."
			} else if _, err := time.Parse("2006-01-02", caducidad); err != nil {
				errors["fecha_caducidad"] = "Fecha caducidad debe ser YYYY-MM-DD."
			}
		} else if caducidad != "" {
			// If they provided a date, validate it anyway to avoid persisting garbage.
			if _, err := time.Parse("2006-01-02", caducidad); err != nil {
				errors["fecha_caducidad"] = "Fecha caducidad debe ser YYYY-MM-DD."
			}
		}

		if len(errors) > 0 {
			w.WriteHeader(http.StatusBadRequest)
			data := productNewData{
				Title:       "Crear producto",
				Subtitle:    "Acción reservada para administradores.",
				SKU:         sku,
				Nombre:      nombre,
				Linea:       linea,
				Cantidad:    cantidad,
				AplicaCad:   aplicaCad,
				Caducidad:   caducidad,
				Errors:      errors,
				CurrentUser: userFromContext(r),
			}
			if err := tmpl.ExecuteTemplate(w, "product_new.html", data); err != nil {
				http.Error(w, "Error al renderizar productos", http.StatusInternalServerError)
			}
			return
		}

		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "No se pudo iniciar la transacción", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		now := time.Now().Format(time.RFC3339)
		if err := upsertProducto(tx, sku, nombre, linea, now); err != nil {
			http.Error(w, "No se pudo guardar el producto", http.StatusInternalServerError)
			return
		}

		baseID := time.Now().UnixNano()
		for j := 0; j < cantidad; j++ {
			unitID := fmt.Sprintf("U-%s-%d", sku, baseID+int64(j))
			var cad any = nil
			if aplicaCad && caducidad != "" {
				cad = caducidad
			}
			if _, err := tx.Exec(
				`INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad) VALUES (?, ?, ?, ?, ?)`,
				unitID, sku, "Disponible", now, cad,
			); err != nil {
				http.Error(w, "No se pudieron crear unidades", http.StatusInternalServerError)
				return
			}
		}

		if err := tx.Commit(); err != nil {
			http.Error(w, "No se pudo confirmar la transacción", http.StatusInternalServerError)
			return
		}

		// Update in-memory catalog (used by inventario/cambio screens).
		productsMu.Lock()
		found := false
		for idx := range products {
			if products[idx].ID == sku {
				products[idx].Name = nombre
				products[idx].Line = linea
				found = true
				break
			}
		}
		if !found {
			products = append(products, productOption{ID: sku, Name: nombre, Line: linea})
		}
		productsMu.Unlock()

		http.Redirect(w, r, "/inventario?mensaje=Producto+agregado", http.StatusSeeOther)
	}))

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		estadoRows, err := db.Query(`
			SELECT CASE WHEN estado = 'Vendida' THEN 'Vendido' ELSE estado END, COUNT(*)
			FROM unidades
			GROUP BY CASE WHEN estado = 'Vendida' THEN 'Vendido' ELSE estado END
			ORDER BY estado`)
		if err != nil {
			http.Error(w, "Error al consultar estados", http.StatusInternalServerError)
			return
		}
		defer estadoRows.Close()

		estadoMap := map[string]int{}
		for estadoRows.Next() {
			var estado string
			var cantidad int
			if err := estadoRows.Scan(&estado, &cantidad); err != nil {
				http.Error(w, "Error al leer estados", http.StatusInternalServerError)
				return
			}
			estadoMap[estado] = cantidad
		}
		if err := estadoRows.Err(); err != nil {
			http.Error(w, "Error al procesar estados", http.StatusInternalServerError)
			return
		}

		estadoOrden := []string{"Disponible", "Cambio", "Vendido"}
		estadoConteos := make([]estadoCount, 0, len(estadoOrden))
		for _, estado := range estadoOrden {
			estadoConteos = append(estadoConteos, estadoCount{
				Estado:   estado,
				Cantidad: estadoMap[estado],
				Link:     "/inventario?estado=" + estado,
			})
		}

		now := time.Now()
		endDate := parseDateOrDefault(r.URL.Query().Get("end_date"), now)
		startDate := parseDateOrDefault(r.URL.Query().Get("start_date"), endDate.AddDate(0, 0, -6))
		if startDate.After(endDate) {
			startDate, endDate = endDate, startDate
		}
		startDate = time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, startDate.Location())
		endDate = time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 0, 0, 0, 0, endDate.Location())
		startStr := startDate.Format("2006-01-02")
		endStr := endDate.Format("2006-01-02")

		var rangeTotal float64
		var rangeCount int
		err = db.QueryRow(`
			SELECT
				COALESCE(SUM(precio_final * cantidad), 0),
				COALESCE(COUNT(*), 0)
			FROM ventas
			WHERE fecha BETWEEN ? AND ?`, startStr, endStr).Scan(&rangeTotal, &rangeCount)
		if err != nil {
			http.Error(w, "Error al consultar ventas por rango", http.StatusInternalServerError)
			return
		}

		metodoRows, err := db.Query(`
			SELECT metodo_pago, COUNT(*), SUM(precio_final * cantidad)
			FROM ventas
			GROUP BY metodo_pago
			ORDER BY SUM(precio_final * cantidad) DESC`)
		if err != nil {
			http.Error(w, "Error al consultar métodos de pago", http.StatusInternalServerError)
			return
		}
		defer metodoRows.Close()

		metodosPago := []metodoPagoTotal{}
		totalPago := 0.0
		for metodoRows.Next() {
			var metodo string
			var cantidad int
			var total float64
			if err := metodoRows.Scan(&metodo, &cantidad, &total); err != nil {
				http.Error(w, "Error al leer métodos de pago", http.StatusInternalServerError)
				return
			}
			metodosPago = append(metodosPago, metodoPagoTotal{
				Metodo:   metodo,
				Cantidad: cantidad,
				Total:    formatCurrency(total),
				Value:    total,
			})
			totalPago += total
		}
		if err := metodoRows.Err(); err != nil {
			http.Error(w, "Error al procesar métodos de pago", http.StatusInternalServerError)
			return
		}

		pieColors := []string{"#2c6bed", "#7d4cf6", "#22a88b", "#f5a524", "#e5484d", "#14b8a6"}
		pieSlices := []pieSlice{}
		offset := 25.0
		for i, metodo := range metodosPago {
			percent := 0.0
			if totalPago > 0 {
				percent = (metodo.Value / totalPago) * 100
			}
			gap := 100 - percent
			color := pieColors[i%len(pieColors)]
			pieSlices = append(pieSlices, pieSlice{
				Metodo:  metodo.Metodo,
				Total:   metodo.Total,
				Percent: percent,
				Offset:  offset,
				Gap:     gap,
				Color:   color,
			})
			offset -= percent
		}

		timeRows, err := db.Query(`
			SELECT fecha, COUNT(*), SUM(precio_final * cantidad)
			FROM ventas
			WHERE fecha BETWEEN ? AND ?
			GROUP BY fecha
			ORDER BY fecha`, startStr, endStr)
		if err != nil {
			http.Error(w, "Error al consultar timeline", http.StatusInternalServerError)
			return
		}
		defer timeRows.Close()

		timelineByDate := make(map[string]timelinePoint)
		for timeRows.Next() {
			var fecha string
			var cantidad int
			var total float64
			if err := timeRows.Scan(&fecha, &cantidad, &total); err != nil {
				http.Error(w, "Error al leer timeline", http.StatusInternalServerError)
				return
			}
			timelineByDate[fecha] = timelinePoint{
				Fecha:    fecha,
				Cantidad: cantidad,
				Total:    formatCurrency(total),
				Value:    total,
			}
		}
		if err := timeRows.Err(); err != nil {
			http.Error(w, "Error al procesar timeline", http.StatusInternalServerError)
			return
		}

		timeline := []timelinePoint{}
		maxTimeline := 0.0
		index := 0
		for cursor := startDate; !cursor.After(endDate); cursor = cursor.AddDate(0, 0, 1) {
			fecha := cursor.Format("2006-01-02")
			point, ok := timelineByDate[fecha]
			if !ok {
				point = timelinePoint{
					Fecha:    fecha,
					Cantidad: 0,
					Total:    formatCurrency(0),
					Value:    0,
				}
			}
			point.Index = index
			timeline = append(timeline, point)
			if point.Value > maxTimeline {
				maxTimeline = point.Value
			}
			index++
		}

		if maxTimeline > 0 {
			for i := range timeline {
				timeline[i].Percent = (timeline[i].Value / maxTimeline) * 100
			}
		}

		data := dashboardData{
			Title:           "Dashboard SSR",
			Subtitle:        "Resumen agregado de inventario y ventas.",
			EstadoConteos:   estadoConteos,
			MetodosPago:     metodosPago,
			PieSlices:       pieSlices,
			PieTotal:        formatCurrency(totalPago),
			MaxTimeline:     maxTimeline,
			MaxTimelineText: formatCurrency(maxTimeline),
			TimelinePoints:  buildTimelinePoints(timeline, 560, 180, 24),
			Timeline:        timeline,
			CurrentUser:     currentUser,
			RangeStart:      startStr,
			RangeEnd:        endStr,
			RangeTotal:      formatCurrency(rangeTotal),
			RangeCount:      rangeCount,
		}

		if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
			http.Error(w, "Error al renderizar el dashboard", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/inventario", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		flash := r.URL.Query().Get("mensaje")
		productsMu.RLock()
		productsSnapshot := make([]productOption, len(products))
		copy(productsSnapshot, products)
		productsMu.RUnlock()

		inventoryProducts := make([]inventoryProduct, 0, len(productsSnapshot))
		for _, product := range productsSnapshot {
			rows, err := db.Query(`
				SELECT id, estado, creado_en, caducidad
				FROM unidades
				WHERE producto_id = ?
				ORDER BY creado_en, id`, product.ID)
			if err != nil {
				http.Error(w, "Error al consultar unidades", http.StatusInternalServerError)
				return
			}

			units := []inventoryUnit{}
			availableCount := 0
			changeCount := 0
			reservedCount := 0
			damagedCount := 0
			fifoIndex := 1
			for rows.Next() {
				var id, estado, creadoEn string
				var caducidad sql.NullString
				if err := rows.Scan(&id, &estado, &creadoEn, &caducidad); err != nil {
					rows.Close()
					http.Error(w, "Error al leer unidades", http.StatusInternalServerError)
					return
				}
				fifo := "-"
				if estado == "Disponible" || estado == "available" {
					fifo = strconv.Itoa(fifoIndex)
					fifoIndex++
					availableCount++
				} else if estado == "Reservada" || estado == "reserved" {
					reservedCount++
				} else if estado == "Cambio" || estado == "swapped" {
					changeCount++
				} else if estado == "Danada" || estado == "Dañada" || estado == "damaged" {
					damagedCount++
				}
				units = append(units, inventoryUnit{
					ID:          id,
					Estado:      estado,
					EstadoClass: estadoClass(estado),
					CreadoEn:    creadoEn,
					Caducidad:   caducidad.String,
					FIFO:        fifo,
				})
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				http.Error(w, "Error al procesar unidades", http.StatusInternalServerError)
				return
			}
			rows.Close()

			estadoLabel := "Disponible"
			estadoClass := "available"
			if availableCount == 0 {
				if reservedCount > 0 {
					estadoLabel = "Reservado"
					estadoClass = "reserved"
				} else if changeCount > 0 {
					estadoLabel = "Cambio"
					estadoClass = "swapped"
				} else if damagedCount > 0 {
					estadoLabel = "Dañado"
					estadoClass = "damaged"
				} else {
					estadoLabel = "Vendido"
					estadoClass = "sold"
				}
			}

			inventoryProducts = append(inventoryProducts, inventoryProduct{
				ID:           product.ID,
				Name:         product.Name,
				Line:         product.Line,
				EstadoLabel:  estadoLabel,
				EstadoClass:  estadoClass,
				Disponible:   availableCount,
				Unidades:     units,
				DisabledSale: availableCount == 0,
			})
		}
		data := inventoryPageData{
			Title:       "Pantalla Inventario (por producto)",
			Subtitle:    "Control por producto con ventas, cambios y auditoría de unidades en FIFO.",
			RoutePrefix: "",
			Flash:       flash,
			Products:    inventoryProducts,
			CurrentUser: currentUser,
		}
		if err := tmpl.ExecuteTemplate(w, "inventario.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/inventario/reservar", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError := func(status int, message string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
		}

		if r.Method != http.MethodPost {
			writeJSONError(http.StatusMethodNotAllowed, "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSONError(http.StatusBadRequest, "No se pudo leer el formulario.")
			return
		}
		productID := strings.TrimSpace(r.FormValue("producto_id"))
		qtyValue := strings.TrimSpace(r.FormValue("cantidad"))
		nota := strings.TrimSpace(r.FormValue("nota"))
		qty, err := strconv.Atoi(qtyValue)
		if productID == "" || err != nil || qty <= 0 {
			writeJSONError(http.StatusBadRequest, "Datos inválidos.")
			return
		}

		tx, err := db.Begin()
		if err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo iniciar la transacción.")
			return
		}
		defer tx.Rollback()

		unitIDs, err := selectAndMarkUnitsByStatus(tx, productID, qty, "Reservada")
		if err != nil {
			if err == errInsufficientStock {
				writeJSONError(http.StatusBadRequest, "No hay stock disponible suficiente para reservar.")
				return
			}
			writeJSONError(http.StatusInternalServerError, "No se pudieron reservar unidades.")
			return
		}

		now := time.Now().Format(time.RFC3339)
		if err := logMovimientos(tx, productID, unitIDs, "reservar", nota, userFromContext(r), now); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo registrar el movimiento.")
			return
		}

		if err := tx.Commit(); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo confirmar la transacción.")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "producto_id": productID, "cantidad": qty})
	})

	mux.HandleFunc("/inventario/dano", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError := func(status int, message string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
		}

		if r.Method != http.MethodPost {
			writeJSONError(http.StatusMethodNotAllowed, "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSONError(http.StatusBadRequest, "No se pudo leer el formulario.")
			return
		}
		productID := strings.TrimSpace(r.FormValue("producto_id"))
		qtyValue := strings.TrimSpace(r.FormValue("cantidad"))
		nota := strings.TrimSpace(r.FormValue("nota"))
		qty, err := strconv.Atoi(qtyValue)
		if productID == "" || err != nil || qty <= 0 {
			writeJSONError(http.StatusBadRequest, "Datos inválidos.")
			return
		}

		tx, err := db.Begin()
		if err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo iniciar la transacción.")
			return
		}
		defer tx.Rollback()

		unitIDs, err := selectAndMarkUnitsByStatus(tx, productID, qty, "Danada")
		if err != nil {
			if err == errInsufficientStock {
				writeJSONError(http.StatusBadRequest, "No hay stock disponible suficiente.")
				return
			}
			writeJSONError(http.StatusInternalServerError, "No se pudo registrar el daño.")
			return
		}

		now := time.Now().Format(time.RFC3339)
		if err := logMovimientos(tx, productID, unitIDs, "dano", nota, userFromContext(r), now); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo registrar el movimiento.")
			return
		}

		if err := tx.Commit(); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo confirmar la transacción.")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "producto_id": productID, "cantidad": qty})
	})

	mux.HandleFunc("/productos/historial", func(w http.ResponseWriter, r *http.Request) {
		productID := strings.TrimSpace(r.URL.Query().Get("producto_id"))
		if productID == "" {
			http.Error(w, "Falta producto_id", http.StatusBadRequest)
			return
		}

		type movimientoRow struct {
			UnidadID string `json:"unidad_id"`
			Tipo     string `json:"tipo"`
			Nota     string `json:"nota"`
			Usuario  string `json:"usuario"`
			Fecha    string `json:"fecha"`
		}
		rows, err := db.Query(`
			SELECT unidad_id, tipo, nota, usuario, fecha
			FROM movimientos
			WHERE producto_id = ?
			ORDER BY fecha DESC
			LIMIT 60
		`, productID)
		if err != nil {
			http.Error(w, "Error al consultar historial", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		movs := []movimientoRow{}
		for rows.Next() {
			var m movimientoRow
			if err := rows.Scan(&m.UnidadID, &m.Tipo, &m.Nota, &m.Usuario, &m.Fecha); err != nil {
				http.Error(w, "Error al leer historial", http.StatusInternalServerError)
				return
			}
			movs = append(movs, m)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "Error al procesar historial", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "producto_id": productID, "movimientos": movs})
	})

	mux.HandleFunc("/venta/new", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		productID := r.URL.Query().Get("producto_id")
		cantidad := 1
		if qty := r.URL.Query().Get("cantidad"); qty != "" {
			if parsed, err := strconv.Atoi(qty); err == nil && parsed > 0 {
				cantidad = parsed
			}
		}

		data := ventaFormData{
			Title:       "Registrar venta",
			ProductoID:  productID,
			Cantidad:    cantidad,
			MetodoPago:  paymentMethods[0],
			MetodoPagos: paymentMethods,
			CurrentUser: currentUser,
		}

		if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/cambio/new", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		productsMu.RLock()
		productsSnapshot := make([]productOption, len(products))
		copy(productsSnapshot, products)
		productsMu.RUnlock()

		productID := r.URL.Query().Get("producto_id")
		if productID == "" {
			productID = productsSnapshot[0].ID
		}
		cantidad := 1
		if qty := r.URL.Query().Get("cantidad"); qty != "" {
			if parsed, err := strconv.Atoi(qty); err == nil && parsed > 0 {
				cantidad = parsed
			}
		}

		selectedProduct, ok := findProduct(productsSnapshot, productID)
		if !ok {
			selectedProduct = productsSnapshot[0]
			productID = selectedProduct.ID
		}

		availableUnits, err := availableUnitsByProduct(db, productID)
		if err != nil {
			http.Error(w, "Error al consultar unidades disponibles", http.StatusInternalServerError)
			return
		}

		salientes := make([]string, 0, cantidad)
		for i := 0; i < cantidad && i < len(availableUnits); i++ {
			salientes = append(salientes, availableUnits[i].ID)
		}

		data := cambioFormData{
			Title:               "Registrar cambio",
			ProductoID:          productID,
			Productos:           productsSnapshot,
			Unidades:            availableUnits,
			Salientes:           salientes,
			SalientesMap:        buildSalientesMap(salientes),
			IncomingMode:        "existing",
			IncomingExistingID:  productsSnapshot[0].ID,
			IncomingExistingQty: cantidad,
			CurrentUser:         currentUser,
		}

		if err := tmpl.ExecuteTemplate(w, "cambio_new.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/venta", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/venta/new", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
			return
		}

		productID := r.FormValue("producto_id")
		qtyValue := r.FormValue("cantidad")
		precioValue := r.FormValue("precio_final_venta")
		metodoPago := r.FormValue("metodo_pago")
		notas := r.FormValue("notas")

		errors := make(map[string]string)
		cantidad, err := strconv.Atoi(qtyValue)
		if err != nil || cantidad <= 0 {
			errors["cantidad"] = "La cantidad debe ser un número positivo."
		}
		if productID == "" {
			errors["producto_id"] = "Selecciona un producto válido."
		}
		if precioValue == "" {
			errors["precio_final_venta"] = "Ingresa el precio final de venta."
		} else if parsed, err := strconv.ParseFloat(precioValue, 64); err != nil || parsed <= 0 {
			errors["precio_final_venta"] = "El precio debe ser un número mayor a 0."
		}

		validMethod := false
		for _, method := range paymentMethods {
			if metodoPago == method {
				validMethod = true
				break
			}
		}
		if !validMethod {
			errors["metodo_pago"] = "Selecciona un método de pago válido."
		}

		if len(errors) > 0 {
			data := ventaFormData{
				Title:       "Registrar venta",
				ProductoID:  productID,
				Cantidad:    cantidad,
				PrecioFinal: precioValue,
				MetodoPago:  metodoPago,
				Notas:       notas,
				Errors:      errors,
				MetodoPagos: paymentMethods,
				CurrentUser: currentUser,
			}
			w.WriteHeader(http.StatusBadRequest)
			if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
				http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
			}
			return
		}

		precioFinal, _ := strconv.ParseFloat(precioValue, 64)
		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "Error al procesar la venta", http.StatusInternalServerError)
			return
		}

		soldUnitIDs, err := selectAndMarkUnitsSold(tx, productID, cantidad)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback venta: %v", rollbackErr)
			}
			if err == errInsufficientStock {
				errors["cantidad"] = "No hay stock disponible suficiente para completar la venta."
				data := ventaFormData{
					Title:       "Registrar venta",
					ProductoID:  productID,
					Cantidad:    cantidad,
					PrecioFinal: precioValue,
					MetodoPago:  metodoPago,
					Notas:       notas,
					Errors:      errors,
					MetodoPagos: paymentMethods,
				}
				w.WriteHeader(http.StatusBadRequest)
				if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
					http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
				}
				return
			}
			http.Error(w, "Error al actualizar inventario", http.StatusInternalServerError)
			return
		}
		now := time.Now().Format(time.RFC3339)
		if err := logMovimientos(tx, productID, soldUnitIDs, "venta", notas, currentUser, now); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback venta log: %v", rollbackErr)
			}
			http.Error(w, "Error al registrar movimiento de venta", http.StatusInternalServerError)
			return
		}

		if _, err := tx.Exec(
			`INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha)
			VALUES (?, ?, ?, ?, ?, ?)`,
			productID, cantidad, precioFinal, metodoPago, notas, now,
		); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback venta insert: %v", rollbackErr)
			}
			http.Error(w, "Error al registrar la venta", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			http.Error(w, "Error al confirmar la venta", http.StatusInternalServerError)
			return
		}

		confirmData := ventaConfirmData{
			Title:       "Venta registrada",
			ProductoID:  productID,
			Cantidad:    cantidad,
			PrecioFinal: precioValue,
			MetodoPago:  metodoPago,
			Notas:       notas,
			CurrentUser: currentUser,
		}
		if err := tmpl.ExecuteTemplate(w, "venta_confirm.html", confirmData); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/cambio", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		productsMu.RLock()
		productsSnapshot := make([]productOption, len(products))
		copy(productsSnapshot, products)
		productsMu.RUnlock()

		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/cambio/new", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
			return
		}

		productID := r.FormValue("producto_id")
		personaCambio := r.FormValue("persona_del_cambio")
		notas := r.FormValue("notas")
		salientes := r.Form["salientes"]
		incomingMode := r.FormValue("incoming_mode")
		incomingExistingID := r.FormValue("incoming_existing_id")
		incomingExistingQtyValue := r.FormValue("incoming_existing_qty")
		incomingNewSKU := r.FormValue("incoming_new_sku")
		incomingNewName := r.FormValue("incoming_new_name")
		incomingNewLine := r.FormValue("incoming_new_line")
		incomingNewQtyValue := r.FormValue("incoming_new_qty")

		errors := make(map[string]string)

		selectedProduct, ok := findProduct(productsSnapshot, productID)
		if !ok {
			errors["producto_id"] = "Selecciona un producto válido."
			selectedProduct = productsSnapshot[0]
			productID = selectedProduct.ID
		}

		if personaCambio == "" {
			errors["persona_del_cambio"] = "Ingresa la persona responsable del cambio."
		}

		availableUnits, err := availableUnitsByProduct(db, productID)
		if err != nil {
			http.Error(w, "Error al consultar unidades disponibles", http.StatusInternalServerError)
			return
		}

		unitLookup := make(map[string]struct{})
		for _, unit := range availableUnits {
			unitLookup[unit.ID] = struct{}{}
		}
		validSalientes := make([]string, 0, len(salientes))
		for _, unitID := range salientes {
			if _, ok := unitLookup[unitID]; ok {
				validSalientes = append(validSalientes, unitID)
			}
		}
		if len(availableUnits) == 0 {
			errors["salientes"] = "No hay unidades disponibles para el producto seleccionado."
		} else if len(validSalientes) == 0 {
			errors["salientes"] = "Selecciona al menos una unidad disponible como saliente."
		}
		salientes = validSalientes

		incomingExistingQty := 0
		if incomingExistingQtyValue != "" {
			if parsed, err := strconv.Atoi(incomingExistingQtyValue); err == nil {
				incomingExistingQty = parsed
			}
		}
		incomingNewQty := 0
		if incomingNewQtyValue != "" {
			if parsed, err := strconv.Atoi(incomingNewQtyValue); err == nil {
				incomingNewQty = parsed
			}
		}

		if incomingMode != "existing" && incomingMode != "new" {
			errors["incoming_mode"] = "Selecciona el tipo de entrada."
		}

		if incomingMode == "existing" {
			if incomingExistingID == "" {
				errors["incoming_existing_id"] = "Selecciona el producto entrante."
			}
			if incomingExistingQty <= 0 {
				errors["incoming_existing_qty"] = "Ingresa una cantidad válida para la entrada."
			}
		} else if incomingMode == "new" {
			if incomingNewSKU == "" {
				errors["incoming_new_sku"] = "Ingresa el SKU del producto nuevo."
			}
			if incomingNewName == "" {
				errors["incoming_new_name"] = "Ingresa el nombre del producto nuevo."
			}
			if incomingNewQty <= 0 {
				errors["incoming_new_qty"] = "Ingresa una cantidad válida para la entrada."
			}
		}

		if len(errors) > 0 {
			data := cambioFormData{
				Title:               "Registrar cambio",
				ProductoID:          productID,
				Productos:           productsSnapshot,
				Unidades:            availableUnits,
				PersonaCambio:       personaCambio,
				Notas:               notas,
				Salientes:           salientes,
				SalientesMap:        buildSalientesMap(salientes),
				IncomingMode:        incomingMode,
				IncomingExistingID:  incomingExistingID,
				IncomingExistingQty: incomingExistingQty,
				IncomingNewSKU:      incomingNewSKU,
				IncomingNewName:     incomingNewName,
				IncomingNewLine:     incomingNewLine,
				IncomingNewQty:      incomingNewQty,
				Errors:              errors,
				CurrentUser:         currentUser,
			}
			w.WriteHeader(http.StatusBadRequest)
			if err := tmpl.ExecuteTemplate(w, "cambio_new.html", data); err != nil {
				http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
			}
			return
		}

		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "Error al iniciar el cambio", http.StatusInternalServerError)
			return
		}

		outgoingQty := len(salientes)
		salientesMarcadas, err := selectAndMarkUnitsByStatus(tx, productID, outgoingQty, "Cambio")
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback cambio: %v", rollbackErr)
			}
			if err == errInsufficientStock {
				errors["salientes"] = "No hay stock disponible suficiente para completar el cambio."
				data := cambioFormData{
					Title:               "Registrar cambio",
					ProductoID:          productID,
					Productos:           productsSnapshot,
					Unidades:            availableUnits,
					PersonaCambio:       personaCambio,
					Notas:               notas,
					Salientes:           salientes,
					SalientesMap:        buildSalientesMap(salientes),
					IncomingMode:        incomingMode,
					IncomingExistingID:  incomingExistingID,
					IncomingExistingQty: incomingExistingQty,
					IncomingNewSKU:      incomingNewSKU,
					IncomingNewName:     incomingNewName,
					IncomingNewLine:     incomingNewLine,
					IncomingNewQty:      incomingNewQty,
					Errors:              errors,
				}
				w.WriteHeader(http.StatusBadRequest)
				if err := tmpl.ExecuteTemplate(w, "cambio_new.html", data); err != nil {
					http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
				}
				return
			}
			http.Error(w, "Error al actualizar unidades salientes", http.StatusInternalServerError)
			return
		}

		now := time.Now().Format(time.RFC3339)
		notaMovimiento := strings.TrimSpace(fmt.Sprintf("%s %s", personaCambio, notas))
		if err := logMovimientos(tx, productID, salientesMarcadas, "cambio_salida", notaMovimiento, currentUser, now); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback cambio log: %v", rollbackErr)
			}
			http.Error(w, "Error al registrar movimiento del cambio", http.StatusInternalServerError)
			return
		}

		entrantes := []string{}
		if incomingMode == "existing" {
			entrantes = buildEntranteIDs("ENT-"+incomingExistingID, incomingExistingQty)
		} else {
			entrantes = buildEntranteIDs("ENT-"+incomingNewSKU, incomingNewQty)
		}

		incomingProductID := incomingExistingID
		incomingQty := incomingExistingQty
		if incomingMode == "new" {
			incomingProductID = incomingNewSKU
			incomingQty = incomingNewQty
		}

		for i := 0; i < incomingQty; i++ {
			unitID := fmt.Sprintf("U-%d-%d", time.Now().UnixNano(), i+1)
			if _, err := tx.Exec(
				`INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad)
				VALUES (?, ?, ?, ?, ?)`,
				unitID, incomingProductID, "Disponible", now, nil,
			); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					log.Printf("rollback cambio insert: %v", rollbackErr)
				}
				http.Error(w, "Error al registrar unidades entrantes", http.StatusInternalServerError)
				return
			}
		}

		if err := tx.Commit(); err != nil {
			http.Error(w, "Error al confirmar el cambio", http.StatusInternalServerError)
			return
		}

		confirmData := cambioConfirmData{
			Title:               "Cambio registrado",
			ProductoID:          productID,
			ProductoNombre:      selectedProduct.Name,
			PersonaCambio:       personaCambio,
			Notas:               notas,
			Salientes:           salientesMarcadas,
			Entrantes:           entrantes,
			IncomingMode:        incomingMode,
			IncomingExistingID:  incomingExistingID,
			IncomingExistingQty: incomingExistingQty,
			IncomingNewSKU:      incomingNewSKU,
			IncomingNewName:     incomingNewName,
			IncomingNewLine:     incomingNewLine,
			IncomingNewQty:      incomingNewQty,
			CurrentUser:         currentUser,
		}

		if err := tmpl.ExecuteTemplate(w, "cambio_confirm.html", confirmData); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/csv/template", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "csv_template.html", struct {
			Title       string
			Subtitle    string
			CurrentUser *User
		}{
			Title:       "Plantilla CSV - Carga masiva",
			Subtitle:    "",
			CurrentUser: userFromContext(r),
		}); err != nil {
			http.Error(w, "Error al renderizar plantilla CSV", http.StatusInternalServerError)
		}
	}))

	mux.HandleFunc("/csv/export", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "csv_export.html", struct {
			Title       string
			Subtitle    string
			CurrentUser *User
		}{
			Title:       "Exportaciones CSV",
			Subtitle:    "",
			CurrentUser: userFromContext(r),
		}); err != nil {
			http.Error(w, "Error al renderizar exportaciones CSV", http.StatusInternalServerError)
		}
	}))

	mux.HandleFunc("/productos/csv", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError := func(status int, message string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
		}

		if r.Method != http.MethodPost {
			writeJSONError(http.StatusMethodNotAllowed, "Método no permitido.")
			return
		}

		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeJSONError(http.StatusBadRequest, "No se pudo leer el archivo.")
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			writeJSONError(http.StatusBadRequest, "Archivo CSV no encontrado.")
			return
		}
		defer file.Close()

		reader := csv.NewReader(file)
		reader.FieldsPerRecord = -1
		records, err := reader.ReadAll()
		if err != nil {
			writeJSONError(http.StatusBadRequest, "No se pudo leer el CSV.")
			return
		}
		if len(records) < 2 {
			writeJSONError(http.StatusBadRequest, "El CSV no contiene filas para procesar.")
			return
		}

		header := make([]string, len(records[0]))
		for i, cell := range records[0] {
			header[i] = strings.ToLower(strings.TrimSpace(cell))
		}
		index := make(map[string]int, len(header))
		for i, name := range header {
			if name == "" {
				continue
			}
			index[name] = i
		}
		required := []string{"sku", "linea", "nombre", "cantidad", "precio_base", "precio_venta", "precio_consultora"}
		for _, col := range required {
			if _, ok := index[col]; !ok {
				writeJSONError(http.StatusBadRequest, "Faltan columnas requeridas en el CSV.")
				return
			}
		}

		get := func(row []string, col string) string {
			pos, ok := index[col]
			if !ok || pos < 0 || pos >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[pos])
		}

		parseCSVFloat := func(value string) (float64, error) {
			value = strings.TrimSpace(value)
			if value == "" {
				return 0, fmt.Errorf("empty")
			}
			value = strings.ReplaceAll(value, ",", ".")
			return strconv.ParseFloat(value, 64)
		}

		parseCSVInt := func(value string) (int, error) {
			value = strings.TrimSpace(value)
			if value == "" {
				return 0, fmt.Errorf("empty")
			}
			return strconv.Atoi(value)
		}

		parseCSVBool := func(value string) (bool, error) {
			value = strings.TrimSpace(strings.ToLower(value))
			if value == "" {
				return false, fmt.Errorf("empty")
			}
			switch value {
			case "true", "1", "si", "sí", "yes":
				return true, nil
			case "false", "0", "no":
				return false, nil
			default:
				return false, fmt.Errorf("invalid")
			}
		}

		resp := csvUploadResponse{}
		tx, err := db.Begin()
		if err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo iniciar la transacción.")
			return
		}

		now := time.Now().Format(time.RFC3339)
		for i, row := range records[1:] {
			rowIndex := i + 1 // matches the UI preview index (1-based excluding header)
			sku := get(row, "sku")
			linea := get(row, "linea")
			nombre := get(row, "nombre")
			cantidadRaw := get(row, "cantidad")

			if sku == "" || linea == "" || nombre == "" {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "SKU, línea y nombre son obligatorios."})
				continue
			}

			cantidad, err := parseCSVInt(cantidadRaw)
			if err != nil || cantidad <= 0 {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Cantidad inválida."})
				continue
			}

			// Validate numeric columns even if we don't persist them yet.
			if _, err := parseCSVFloat(get(row, "precio_base")); err != nil {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Precio base inválido."})
				continue
			}
			if _, err := parseCSVFloat(get(row, "precio_venta")); err != nil {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Precio venta inválido."})
				continue
			}
			if _, err := parseCSVFloat(get(row, "precio_consultora")); err != nil {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Precio consultora inválido."})
				continue
			}

			fechaCaducidad := get(row, "fecha_caducidad")
			aplicaCadRaw := get(row, "aplica_caducidad")
			aplicaCad := false
			if aplicaCadRaw != "" {
				parsed, err := parseCSVBool(aplicaCadRaw)
				if err != nil {
					resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Aplica caducidad debe ser true/false."})
					continue
				}
				aplicaCad = parsed
			}
			if aplicaCad && fechaCaducidad == "" {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Fecha caducidad requerida si aplica."})
				continue
			}
			if fechaCaducidad != "" {
				if _, err := time.Parse("2006-01-02", fechaCaducidad); err != nil {
					resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Fecha caducidad debe ser YYYY-MM-DD."})
					continue
				}
			}

			if _, err := tx.Exec("SAVEPOINT csv_row"); err != nil {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Error al preparar la fila."})
				continue
			}

			// Persist catalog.
			if err := upsertProducto(tx, sku, nombre, linea, now); err != nil {
				_, _ = tx.Exec("ROLLBACK TO csv_row")
				_, _ = tx.Exec("RELEASE csv_row")
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Error al guardar producto."})
				continue
			}

			// Update in-memory catalog (used by inventario/cambio screens).
			productsMu.Lock()
			found := false
			for idx := range products {
				if products[idx].ID == sku {
					products[idx].Name = nombre
					products[idx].Line = linea
					found = true
					break
				}
			}
			if !found {
				products = append(products, productOption{ID: sku, Name: nombre, Line: linea})
				resp.CreatedProducts++
			} else {
				resp.UpdatedProducts++
			}
			productsMu.Unlock()

			// Insert units into DB (inventory source of truth).
			baseID := time.Now().UnixNano()
			rowFailed := false
			for j := 0; j < cantidad; j++ {
				unitID := fmt.Sprintf("U-%s-%d", sku, baseID+int64(j))
				var caducidad any = nil
				if aplicaCad && fechaCaducidad != "" {
					caducidad = fechaCaducidad
				}
				if _, err := tx.Exec(
					`INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad) VALUES (?, ?, ?, ?, ?)`,
					unitID, sku, "Disponible", now, caducidad,
				); err != nil {
					_, _ = tx.Exec("ROLLBACK TO csv_row")
					_, _ = tx.Exec("RELEASE csv_row")
					resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Error al crear unidades."})
					rowFailed = true
					break
				}
				resp.CreatedUnits++
			}

			if rowFailed {
				continue
			}
			_, _ = tx.Exec("RELEASE csv_row")
		}

		if err := tx.Commit(); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo guardar el CSV.")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/inventario", http.StatusFound)
	})

	addr := ":" + port
	log.Printf("Servidor activo en http://localhost:%s/inventario", port)
	if err := http.ListenAndServe(addr, authMiddleware(db, mux)); err != nil {
		log.Fatal(err)
	}
}
