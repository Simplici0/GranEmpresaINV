package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type inventoryPageData struct {
	Title           string
	Subtitle        string
	RoutePrefix     string
	Flash           string
	CurrentUserName string
	IsAdmin         bool
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
	IsAdmin             bool
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
	IsAdmin         bool
}

type adminUsersListData struct {
	Title string
	Users []appUser
	Flash string
}

type adminUserFormData struct {
	Title       string
	User        appUser
	Errors      map[string]string
	Flash       string
	NewPassword string
}

type appUser struct {
	ID           int
	Name         string
	Email        string
	Role         string
	Active       bool
	PasswordHash string
	PasswordSalt string
}

type authResult struct {
	User   *appUser
	Status int
	Err    error
}

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

func createUser(db *sql.DB, name, email, role, password string, active bool) (*appUser, error) {
	if name == "" || email == "" || role == "" {
		return nil, errors.New("missing fields")
	}
	if role != "admin" && role != "employee" {
		return nil, errors.New("invalid role")
	}
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}
	passwordHash := hashPassword(password, salt)
	activeValue := 0
	if active {
		activeValue = 1
	}
	now := time.Now().Format(time.RFC3339)
	result, err := db.Exec(`INSERT INTO users (name, email, role, active, password_hash, password_salt, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, name, email, role, activeValue, passwordHash, salt, now)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &appUser{
		ID:           int(id),
		Name:         name,
		Email:        email,
		Role:         role,
		Active:       active,
		PasswordHash: passwordHash,
		PasswordSalt: salt,
	}, nil
}

func getUserByEmail(db *sql.DB, email string) (*appUser, error) {
	row := db.QueryRow(`SELECT id, name, email, role, active, password_hash, password_salt
		FROM users WHERE email = ?`, email)
	var user appUser
	var activeValue int
	if err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Role, &activeValue, &user.PasswordHash, &user.PasswordSalt); err != nil {
		return nil, err
	}
	user.Active = activeValue == 1
	return &user, nil
}

func getUserByID(db *sql.DB, id int) (*appUser, error) {
	row := db.QueryRow(`SELECT id, name, email, role, active, password_hash, password_salt
		FROM users WHERE id = ?`, id)
	var user appUser
	var activeValue int
	if err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Role, &activeValue, &user.PasswordHash, &user.PasswordSalt); err != nil {
		return nil, err
	}
	user.Active = activeValue == 1
	return &user, nil
}

func authenticateUser(r *http.Request, db *sql.DB) authResult {
	email, password, ok := r.BasicAuth()
	if !ok || email == "" || password == "" {
		return authResult{Status: http.StatusUnauthorized, Err: errors.New("missing credentials")}
	}
	user, err := getUserByEmail(db, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authResult{Status: http.StatusUnauthorized, Err: errors.New("invalid credentials")}
		}
		return authResult{Status: http.StatusInternalServerError, Err: err}
	}
	if hashPassword(password, user.PasswordSalt) != user.PasswordHash {
		return authResult{Status: http.StatusUnauthorized, Err: errors.New("invalid credentials")}
	}
	if !user.Active {
		return authResult{Status: http.StatusForbidden, Err: errors.New("user inactive")}
	}
	return authResult{User: user, Status: http.StatusOK}
}

func withAuth(db *sql.DB, allowedRoles []string, handler func(http.ResponseWriter, *http.Request, *appUser)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authenticateUser(r, db)
		if result.Status != http.StatusOK {
			if result.Status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Basic realm="GranEmpresa"`)
			}
			http.Error(w, "Acceso no autorizado", result.Status)
			return
		}
		if len(allowedRoles) > 0 && !roleAllowed(result.User.Role, allowedRoles) {
			http.Error(w, "No autorizado para esta acción", http.StatusForbidden)
			return
		}
		handler(w, r, result.User)
	}
}

func generateSalt() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashPassword(password, salt string) string {
	sum := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(sum[:])
}

func randomPassword() (string, error) {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func roleAllowed(role string, allowed []string) bool {
	for _, allowedRole := range allowed {
		if role == allowedRole {
			return true
		}
	}
	return false
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
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		role TEXT NOT NULL,
		active INTEGER NOT NULL DEFAULT 1,
		password_hash TEXT NOT NULL,
		password_salt TEXT NOT NULL,
		created_at TEXT NOT NULL
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

	var usersCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&usersCount); err != nil {
		return nil, err
	}
	if usersCount == 0 {
		if _, err := createUser(db, "Administrador", "admin@granempresa.local", "admin", "admin123", true); err != nil {
			return nil, err
		}
		if _, err := createUser(db, "Empleado", "empleado@granempresa.local", "employee", "empleado123", true); err != nil {
			return nil, err
		}
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
		"templates/dashboard.html",
		"templates/inventario.html",
		"templates/venta_new.html",
		"templates/venta_confirm.html",
		"templates/cambio_new.html",
		"templates/cambio_confirm.html",
		"templates/csv_template.html",
		"templates/csv_export.html",
		"templates/admin_users_list.html",
		"templates/admin_users_new.html",
		"templates/admin_users_edit.html",
	))

	paymentMethods := []string{"Efectivo", "Transferencia", "Tarjeta", "Nequi", "Daviplata", "Bre-B"}

	db, err := initDB(dbPath, paymentMethods)
	if err != nil {
		log.Fatalf("Error al abrir SQLite: %v", err)
	}
	defer db.Close()

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
		IsAdmin     bool
	}

	type ventaConfirmData struct {
		Title       string
		ProductoID  string
		Cantidad    int
		PrecioFinal string
		MetodoPago  string
		Notas       string
	}

	http.HandleFunc("/dashboard", withAuth(db, []string{"admin", "employee"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
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
			IsAdmin:         user.Role == "admin",
		}

		if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
			http.Error(w, "Error al renderizar el dashboard", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/inventario", withAuth(db, []string{"admin", "employee"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
		flash := r.URL.Query().Get("mensaje")
		data := inventoryPageData{
			Title:           "Pantalla Inventario (por producto)",
			Subtitle:        "Control por producto con ventas, cambios y auditoría de unidades en FIFO.",
			RoutePrefix:     "",
			Flash:           flash,
			CurrentUserName: user.Name,
			IsAdmin:         user.Role == "admin",
		}
		if err := tmpl.ExecuteTemplate(w, "inventario.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/venta/new", withAuth(db, []string{"admin", "employee"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
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
			IsAdmin:     user.Role == "admin",
		}

		if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/cambio/new", withAuth(db, []string{"admin", "employee"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
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
			IsAdmin:             user.Role == "admin",
		}

		if err := tmpl.ExecuteTemplate(w, "cambio_new.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/venta", withAuth(db, []string{"admin", "employee"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
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
				IsAdmin:     user.Role == "admin",
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
		}
		if err := tmpl.ExecuteTemplate(w, "venta_confirm.html", confirmData); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/cambio", withAuth(db, []string{"admin", "employee"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
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
		if incomingMode == "new" && user.Role != "admin" {
			errors["incoming_mode"] = "Solo administración puede crear productos nuevos."
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
				IsAdmin:             user.Role == "admin",
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
		}

		if err := tmpl.ExecuteTemplate(w, "cambio_confirm.html", confirmData); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/csv/template", withAuth(db, []string{"admin"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
		if err := tmpl.ExecuteTemplate(w, "csv_template.html", struct {
			Title string
		}{
			Title: "Plantilla CSV - Carga masiva",
		}); err != nil {
			http.Error(w, "Error al renderizar plantilla CSV", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/csv/export", withAuth(db, []string{"admin"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
		if err := tmpl.ExecuteTemplate(w, "csv_export.html", struct {
			Title string
		}{
			Title: "Exportaciones CSV",
		}); err != nil {
			http.Error(w, "Error al renderizar exportaciones CSV", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/admin/users", withAuth(db, []string{"admin"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
				return
			}
			name := strings.TrimSpace(r.FormValue("name"))
			email := strings.TrimSpace(r.FormValue("email"))
			role := r.FormValue("role")
			password := r.FormValue("password")

			errors := make(map[string]string)
			if name == "" {
				errors["name"] = "El nombre es obligatorio."
			}
			if email == "" || !strings.Contains(email, "@") {
				errors["email"] = "Ingresa un email válido."
			}
			if role != "admin" && role != "employee" {
				errors["role"] = "Selecciona un rol válido."
			}

			if len(errors) > 0 {
				w.WriteHeader(http.StatusBadRequest)
				if err := tmpl.ExecuteTemplate(w, "admin_users_new.html", adminUserFormData{
					Title:  "Nuevo usuario",
					User:   appUser{Name: name, Email: email, Role: role, Active: true},
					Errors: errors,
				}); err != nil {
					http.Error(w, "Error al renderizar formulario", http.StatusInternalServerError)
				}
				return
			}

			newPassword := ""
			if password == "" {
				generated, err := randomPassword()
				if err != nil {
					http.Error(w, "No se pudo generar la contraseña", http.StatusInternalServerError)
					return
				}
				password = generated
				newPassword = generated
			}

			if _, err := createUser(db, name, email, role, password, true); err != nil {
				errors["form"] = "No se pudo crear el usuario. Verifica que el email no esté duplicado."
				w.WriteHeader(http.StatusBadRequest)
				if err := tmpl.ExecuteTemplate(w, "admin_users_new.html", adminUserFormData{
					Title:  "Nuevo usuario",
					User:   appUser{Name: name, Email: email, Role: role, Active: true},
					Errors: errors,
				}); err != nil {
					http.Error(w, "Error al renderizar formulario", http.StatusInternalServerError)
				}
				return
			}

			if err := tmpl.ExecuteTemplate(w, "admin_users_new.html", adminUserFormData{
				Title:       "Nuevo usuario",
				Flash:       "Usuario creado correctamente.",
				NewPassword: newPassword,
			}); err != nil {
				http.Error(w, "Error al renderizar formulario", http.StatusInternalServerError)
			}
			return
		}

		rows, err := db.Query(`SELECT id, name, email, role, active FROM users ORDER BY id`)
		if err != nil {
			http.Error(w, "Error al consultar usuarios", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		users := []appUser{}
		for rows.Next() {
			var userRow appUser
			var activeValue int
			if err := rows.Scan(&userRow.ID, &userRow.Name, &userRow.Email, &userRow.Role, &activeValue); err != nil {
				http.Error(w, "Error al leer usuarios", http.StatusInternalServerError)
				return
			}
			userRow.Active = activeValue == 1
			users = append(users, userRow)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "Error al procesar usuarios", http.StatusInternalServerError)
			return
		}

		if err := tmpl.ExecuteTemplate(w, "admin_users_list.html", adminUsersListData{
			Title: "Usuarios",
			Users: users,
			Flash: r.URL.Query().Get("mensaje"),
		}); err != nil {
			http.Error(w, "Error al renderizar usuarios", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/admin/users/new", withAuth(db, []string{"admin"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
		if err := tmpl.ExecuteTemplate(w, "admin_users_new.html", adminUserFormData{
			Title: "Nuevo usuario",
			User:  appUser{Active: true, Role: "employee"},
		}); err != nil {
			http.Error(w, "Error al renderizar formulario", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/admin/users/", withAuth(db, []string{"admin"}, func(w http.ResponseWriter, r *http.Request, user *appUser) {
		trimmed := strings.TrimPrefix(r.URL.Path, "/admin/users/")
		parts := strings.Split(strings.Trim(trimmed, "/"), "/")
		if len(parts) != 2 || parts[1] != "edit" {
			http.NotFound(w, r)
			return
		}
		id, err := strconv.Atoi(parts[0])
		if err != nil {
			http.NotFound(w, r)
			return
		}

		targetUser, err := getUserByID(db, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "Error al consultar usuario", http.StatusInternalServerError)
			return
		}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
				return
			}
			role := r.FormValue("role")
			active := r.FormValue("active") == "on"
			resetPassword := r.FormValue("reset_password") == "1"

			errors := make(map[string]string)
			if role != "admin" && role != "employee" {
				errors["role"] = "Selecciona un rol válido."
			}

			if len(errors) > 0 {
				targetUser.Role = role
				targetUser.Active = active
				w.WriteHeader(http.StatusBadRequest)
				if err := tmpl.ExecuteTemplate(w, "admin_users_edit.html", adminUserFormData{
					Title:  "Editar usuario",
					User:   *targetUser,
					Errors: errors,
				}); err != nil {
					http.Error(w, "Error al renderizar formulario", http.StatusInternalServerError)
				}
				return
			}

			activeValue := 0
			if active {
				activeValue = 1
			}
			if _, err := db.Exec(`UPDATE users SET role = ?, active = ? WHERE id = ?`, role, activeValue, targetUser.ID); err != nil {
				http.Error(w, "Error al actualizar usuario", http.StatusInternalServerError)
				return
			}

			newPassword := ""
			if resetPassword {
				generated, err := randomPassword()
				if err != nil {
					http.Error(w, "No se pudo generar la contraseña", http.StatusInternalServerError)
					return
				}
				salt, err := generateSalt()
				if err != nil {
					http.Error(w, "No se pudo generar la contraseña", http.StatusInternalServerError)
					return
				}
				hashed := hashPassword(generated, salt)
				if _, err := db.Exec(`UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?`, hashed, salt, targetUser.ID); err != nil {
					http.Error(w, "Error al reiniciar la contraseña", http.StatusInternalServerError)
					return
				}
				newPassword = generated
			}

			updatedUser, err := getUserByID(db, targetUser.ID)
			if err != nil {
				http.Error(w, "Error al consultar usuario", http.StatusInternalServerError)
				return
			}
			if err := tmpl.ExecuteTemplate(w, "admin_users_edit.html", adminUserFormData{
				Title:       "Editar usuario",
				User:        *updatedUser,
				Flash:       "Usuario actualizado.",
				NewPassword: newPassword,
			}); err != nil {
				http.Error(w, "Error al renderizar formulario", http.StatusInternalServerError)
			}
			return
		}

		if err := tmpl.ExecuteTemplate(w, "admin_users_edit.html", adminUserFormData{
			Title: "Editar usuario",
			User:  *targetUser,
		}); err != nil {
			http.Error(w, "Error al renderizar formulario", http.StatusInternalServerError)
		}
	}))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/inventario", http.StatusFound)
	})

	addr := ":" + port
	log.Printf("Servidor activo en http://localhost:%s/inventario", port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
