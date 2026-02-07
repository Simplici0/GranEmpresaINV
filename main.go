package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

type inventoryPageData struct {
	Title       string
	Subtitle    string
	RoutePrefix string
	Flash       string
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

type cambioFormData struct {
	Title               string
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
	PeriodosTotales []periodTotal
	MetodosPago     []metodoPagoTotal
	PieSlices       []pieSlice
	PieTotal        string
	MaxPeriodo      float64
	MaxTimeline     float64
	MaxTimelineText string
	TimelinePoints  string
	Timeline        []timelinePoint
	CurrentUser     *User
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

func formatCurrency(value float64) string {
	return fmt.Sprintf("$%.0f", value)
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
		if r.URL.Path == "/login" || r.URL.Path == "/health" {
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
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS ventas (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		producto_id TEXT NOT NULL,
		cantidad INTEGER NOT NULL,
		precio_final REAL NOT NULL,
		metodo_pago TEXT NOT NULL,
		fecha TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ventas_fecha ON ventas (fecha);
	CREATE INDEX IF NOT EXISTS idx_ventas_metodo ON ventas (metodo_pago);

	CREATE TABLE IF NOT EXISTS unidades (
		id TEXT PRIMARY KEY,
		producto_id TEXT NOT NULL,
		estado TEXT NOT NULL,
		creado_en TEXT NOT NULL
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
	stmt, err := tx.Prepare(`INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, fecha)
		VALUES (?, ?, ?, ?, ?)`)
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
			if _, err := stmt.Exec(productoID, cantidad, precio, metodo, date); err != nil {
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
	stmt, err := tx.Prepare(`INSERT INTO unidades (id, producto_id, estado, creado_en)
		VALUES (?, ?, ?, ?)`)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("prepare unidades: %w (rollback: %v)", err, rollbackErr)
		}
		return err
	}
	defer stmt.Close()

	statuses := []string{"Disponible", "Vendida", "Cambio"}
	products := []string{"P-001", "P-002", "P-003"}
	now := time.Now().Format(time.RFC3339)
	for i := 1; i <= 36; i++ {
		id := fmt.Sprintf("U-%03d", i)
		productoID := products[i%len(products)]
		estado := statuses[i%len(statuses)]
		if _, err := stmt.Exec(id, productoID, estado, now); err != nil {
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

	products := []productOption{
		{
			ID:    "P-001",
			Name:  "Proteína Balance 500g",
			Line:  "Nutrición",
			Units: []unitOption{{ID: "U-001"}, {ID: "U-002"}, {ID: "U-003"}},
		},
		{
			ID:    "P-002",
			Name:  "Crema Regeneradora",
			Line:  "Dermocosmética",
			Units: []unitOption{{ID: "U-101"}, {ID: "U-102"}, {ID: "U-103"}, {ID: "U-104"}},
		},
		{
			ID:    "P-003",
			Name:  "Leche Pediátrica Premium",
			Line:  "Pediatría",
			Units: []unitOption{{ID: "U-201"}},
		},
	}

	type ventaFormData struct {
		Title       string
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
		CurrentUser *User
	}

	mux := http.NewServeMux()

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
		http.Error(w, "Creación de productos pendiente de implementación.", http.StatusNotImplemented)
	}))

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		estadoRows, err := db.Query(`
			SELECT estado, COUNT(*)
			FROM unidades
			GROUP BY estado
			ORDER BY estado`)
		if err != nil {
			http.Error(w, "Error al consultar estados", http.StatusInternalServerError)
			return
		}
		defer estadoRows.Close()

		estadoConteos := []estadoCount{}
		for estadoRows.Next() {
			var estado string
			var cantidad int
			if err := estadoRows.Scan(&estado, &cantidad); err != nil {
				http.Error(w, "Error al leer estados", http.StatusInternalServerError)
				return
			}
			estadoConteos = append(estadoConteos, estadoCount{
				Estado:   estado,
				Cantidad: cantidad,
				Link:     "/inventario?estado=" + estado,
			})
		}
		if err := estadoRows.Err(); err != nil {
			http.Error(w, "Error al procesar estados", http.StatusInternalServerError)
			return
		}

		var hoyTotal, semanaTotal, mesTotal float64
		err = db.QueryRow(`
			SELECT
				COALESCE(SUM(CASE WHEN fecha = date('now') THEN precio_final END), 0),
				COALESCE(SUM(CASE WHEN fecha >= date('now','-6 days') THEN precio_final END), 0),
				COALESCE(SUM(CASE WHEN fecha >= date('now','start of month') THEN precio_final END), 0)
			FROM ventas`).Scan(&hoyTotal, &semanaTotal, &mesTotal)
		if err != nil {
			http.Error(w, "Error al consultar ventas", http.StatusInternalServerError)
			return
		}

		periodosTotales := []periodTotal{
			{Label: "Hoy", Total: formatCurrency(hoyTotal), Range: "Ventas del día", Value: hoyTotal},
			{Label: "Últimos 7 días", Total: formatCurrency(semanaTotal), Range: "Acumulado semanal", Value: semanaTotal},
			{Label: "Mes actual", Total: formatCurrency(mesTotal), Range: "Acumulado del mes", Value: mesTotal},
		}
		maxPeriodo := 0.0
		for _, periodo := range periodosTotales {
			if periodo.Value > maxPeriodo {
				maxPeriodo = periodo.Value
			}
		}
		if maxPeriodo > 0 {
			for i := range periodosTotales {
				periodosTotales[i].Percent = (periodosTotales[i].Value / maxPeriodo) * 100
			}
		}

		metodoRows, err := db.Query(`
			SELECT metodo_pago, COUNT(*), SUM(precio_final)
			FROM ventas
			GROUP BY metodo_pago
			ORDER BY SUM(precio_final) DESC`)
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
			SELECT fecha, COUNT(*), SUM(precio_final)
			FROM ventas
			WHERE fecha >= date('now','-13 days')
			GROUP BY fecha
			ORDER BY fecha`)
		if err != nil {
			http.Error(w, "Error al consultar timeline", http.StatusInternalServerError)
			return
		}
		defer timeRows.Close()

		timeline := []timelinePoint{}
		maxTimeline := 0.0
		index := 0
		for timeRows.Next() {
			var fecha string
			var cantidad int
			var total float64
			if err := timeRows.Scan(&fecha, &cantidad, &total); err != nil {
				http.Error(w, "Error al leer timeline", http.StatusInternalServerError)
				return
			}
			timeline = append(timeline, timelinePoint{
				Fecha:    fecha,
				Cantidad: cantidad,
				Total:    formatCurrency(total),
				Value:    total,
				Index:    index,
			})
			if total > maxTimeline {
				maxTimeline = total
			}
			index++
		}
		if err := timeRows.Err(); err != nil {
			http.Error(w, "Error al procesar timeline", http.StatusInternalServerError)
			return
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
			PeriodosTotales: periodosTotales,
			MetodosPago:     metodosPago,
			PieSlices:       pieSlices,
			PieTotal:        formatCurrency(totalPago),
			MaxPeriodo:      maxPeriodo,
			MaxTimeline:     maxTimeline,
			MaxTimelineText: formatCurrency(maxTimeline),
			TimelinePoints:  buildTimelinePoints(timeline, 560, 180, 24),
			Timeline:        timeline,
			CurrentUser:     currentUser,
		}

		if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
			http.Error(w, "Error al renderizar el dashboard", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/inventario", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		flash := r.URL.Query().Get("mensaje")
		data := inventoryPageData{
			Title:       "Pantalla Inventario (por producto)",
			Subtitle:    "Control por producto con ventas, cambios y auditoría de unidades en FIFO.",
			RoutePrefix: "",
			Flash:       flash,
			CurrentUser: currentUser,
		}
		if err := tmpl.ExecuteTemplate(w, "inventario.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
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
		productID := r.URL.Query().Get("producto_id")
		if productID == "" {
			productID = products[0].ID
		}
		cantidad := 1
		if qty := r.URL.Query().Get("cantidad"); qty != "" {
			if parsed, err := strconv.Atoi(qty); err == nil && parsed > 0 {
				cantidad = parsed
			}
		}

		selectedProduct, ok := findProduct(products, productID)
		if !ok {
			selectedProduct = products[0]
			productID = selectedProduct.ID
		}

		salientes := make([]string, 0, cantidad)
		for i := 0; i < cantidad && i < len(selectedProduct.Units); i++ {
			salientes = append(salientes, selectedProduct.Units[i].ID)
		}

		data := cambioFormData{
			Title:               "Registrar cambio",
			ProductoID:          productID,
			Productos:           products,
			Unidades:            selectedProduct.Units,
			Salientes:           salientes,
			SalientesMap:        buildSalientesMap(salientes),
			IncomingMode:        "existing",
			IncomingExistingID:  products[0].ID,
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

		selectedProduct, ok := findProduct(products, productID)
		if !ok {
			errors["producto_id"] = "Selecciona un producto válido."
			selectedProduct = products[0]
			productID = selectedProduct.ID
		}

		if personaCambio == "" {
			errors["persona_del_cambio"] = "Ingresa la persona responsable del cambio."
		}

		unitLookup := make(map[string]struct{})
		for _, unit := range selectedProduct.Units {
			unitLookup[unit.ID] = struct{}{}
		}
		validSalientes := make([]string, 0, len(salientes))
		for _, unitID := range salientes {
			if _, ok := unitLookup[unitID]; ok {
				validSalientes = append(validSalientes, unitID)
			}
		}
		if len(validSalientes) == 0 {
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
				Productos:           products,
				Unidades:            selectedProduct.Units,
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

		entrantes := []string{}
		if incomingMode == "existing" {
			entrantes = buildEntranteIDs("ENT-"+incomingExistingID, incomingExistingQty)
		} else {
			entrantes = buildEntranteIDs("ENT-"+incomingNewSKU, incomingNewQty)
		}

		confirmData := cambioConfirmData{
			Title:               "Cambio registrado",
			ProductoID:          productID,
			ProductoNombre:      selectedProduct.Name,
			PersonaCambio:       personaCambio,
			Notas:               notas,
			Salientes:           salientes,
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
			CurrentUser *User
		}{
			Title:       "Plantilla CSV - Carga masiva",
			CurrentUser: userFromContext(r),
		}); err != nil {
			http.Error(w, "Error al renderizar plantilla CSV", http.StatusInternalServerError)
		}
	}))

	mux.HandleFunc("/csv/export", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "csv_export.html", struct {
			Title       string
			CurrentUser *User
		}{
			Title:       "Exportaciones CSV",
			CurrentUser: userFromContext(r),
		}); err != nil {
			http.Error(w, "Error al renderizar exportaciones CSV", http.StatusInternalServerError)
		}
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
