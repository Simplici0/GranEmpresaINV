package main

import (
	"database/sql"
	"encoding/json"
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
	Title        string
	Subtitle     string
	RoutePrefix  string
	Flash        string
	ProductsJSON template.JS
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

type inventoryUnit struct {
	ID       string `json:"id"`
	Received string `json:"received"`
	Expires  string `json:"expires"`
	Location string `json:"location"`
	Status   string `json:"status"`
}

type inventoryProduct struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Line   string          `json:"line"`
	Status string          `json:"status"`
	Units  []inventoryUnit `json:"units"`
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
}

func findProduct(products []productOption, id string) (productOption, bool) {
	for _, product := range products {
		if product.ID == id {
			return product, true
		}
	}
	return productOption{}, false
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
	CREATE TABLE IF NOT EXISTS productos (
		id TEXT PRIMARY KEY,
		sku TEXT,
		nombre TEXT NOT NULL,
		linea TEXT NOT NULL,
		precio_base REAL
	);

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

	CREATE TABLE IF NOT EXISTS cambios (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		producto_saliente_id TEXT NOT NULL,
		unidades_ids TEXT NOT NULL,
		persona_cambio TEXT NOT NULL,
		registrado_en TEXT NOT NULL,
		producto_entrante_id TEXT,
		producto_entrante_detalle TEXT NOT NULL
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

	var productosCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM productos").Scan(&productosCount); err != nil {
		return nil, err
	}
	if productosCount == 0 {
		if err := seedProductos(db); err != nil {
			return nil, err
		}
	}

	if unidadesCount == 0 {
		if err := seedUnidades(db); err != nil {
			return nil, err
		}
	}

	return db, nil
}

func seedProductos(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO productos (id, sku, nombre, linea, precio_base)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("prepare productos: %w (rollback: %v)", err, rollbackErr)
		}
		return err
	}
	defer stmt.Close()

	products := []struct {
		ID    string
		Name  string
		Line  string
		Price float64
	}{
		{ID: "P-001", Name: "Proteína Balance 500g", Line: "Nutrición", Price: 120000},
		{ID: "P-002", Name: "Crema Regeneradora", Line: "Dermocosmética", Price: 89000},
		{ID: "P-003", Name: "Leche Pediátrica Premium", Line: "Pediatría", Price: 105000},
	}

	for _, product := range products {
		if _, err := stmt.Exec(product.ID, product.ID, product.Name, product.Line, product.Price); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return fmt.Errorf("insert productos: %w (rollback: %v)", err, rollbackErr)
			}
			return err
		}
	}

	return tx.Commit()
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

func fetchProductOptions(db *sql.DB) ([]productOption, error) {
	rows, err := db.Query(`SELECT id, nombre, linea FROM productos ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	products := []productOption{}
	for rows.Next() {
		var id, name, line string
		if err := rows.Scan(&id, &name, &line); err != nil {
			return nil, err
		}
		products = append(products, productOption{
			ID:   id,
			Name: name,
			Line: line,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return products, nil
}

func fetchProductByID(db *sql.DB, productID string) (productOption, error) {
	var product productOption
	err := db.QueryRow(`SELECT id, nombre, linea FROM productos WHERE id = ?`, productID).Scan(&product.ID, &product.Name, &product.Line)
	return product, err
}

func fetchAvailableUnits(db *sql.DB, productID string) ([]unitOption, error) {
	rows, err := db.Query(`SELECT id FROM unidades WHERE producto_id = ? AND estado = 'Disponible' ORDER BY creado_en, id`, productID)
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

func fetchInventoryProducts(db *sql.DB) ([]inventoryProduct, error) {
	productRows, err := db.Query(`SELECT id, nombre, linea FROM productos ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer productRows.Close()

	products := []inventoryProduct{}
	productIndex := map[string]int{}
	for productRows.Next() {
		var id, name, line string
		if err := productRows.Scan(&id, &name, &line); err != nil {
			return nil, err
		}
		productIndex[id] = len(products)
		products = append(products, inventoryProduct{
			ID:     id,
			Name:   name,
			Line:   line,
			Status: "available",
			Units:  []inventoryUnit{},
		})
	}
	if err := productRows.Err(); err != nil {
		return nil, err
	}

	unitRows, err := db.Query(`SELECT id, producto_id, estado, creado_en FROM unidades ORDER BY creado_en, id`)
	if err != nil {
		return nil, err
	}
	defer unitRows.Close()

	for unitRows.Next() {
		var id, productID, estado, creadoEn string
		if err := unitRows.Scan(&id, &productID, &estado, &creadoEn); err != nil {
			return nil, err
		}
		idx, ok := productIndex[productID]
		if !ok {
			continue
		}
		status := mapEstadoToStatus(estado)
		unit := inventoryUnit{
			ID:       id,
			Received: creadoEn,
			Expires:  creadoEn,
			Location: "-",
			Status:   status,
		}
		products[idx].Units = append(products[idx].Units, unit)
	}
	if err := unitRows.Err(); err != nil {
		return nil, err
	}

	for i := range products {
		products[i].Status = deriveProductStatus(products[i].Units)
	}

	return products, nil
}

func mapEstadoToStatus(estado string) string {
	switch estado {
	case "Disponible":
		return "available"
	case "Vendida":
		return "sold"
	case "Cambio":
		return "swapped"
	default:
		return "available"
	}
}

func deriveProductStatus(units []inventoryUnit) string {
	if len(units) == 0 {
		return "available"
	}
	allSold := true
	allSwapped := true
	for _, unit := range units {
		if unit.Status != "sold" {
			allSold = false
		}
		if unit.Status != "swapped" {
			allSwapped = false
		}
		if unit.Status == "available" {
			return "available"
		}
	}
	if allSold {
		return "sold"
	}
	if allSwapped {
		return "swapped"
	}
	return "available"
}

func buildUnitIDs(prefix string, qty int) []string {
	ids := make([]string, 0, qty)
	for i := 0; i < qty; i++ {
		ids = append(ids, fmt.Sprintf("%s-%d", prefix, i+1))
	}
	return ids
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
	))

	paymentMethods := []string{"Efectivo", "Transferencia", "Tarjeta", "Nequi", "Daviplata", "Bre-B"}

	db, err := initDB(dbPath, paymentMethods)
	if err != nil {
		log.Fatalf("Error al abrir SQLite: %v", err)
	}
	defer db.Close()

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
	}

	type ventaConfirmData struct {
		Title       string
		ProductoID  string
		Cantidad    int
		PrecioFinal string
		MetodoPago  string
		Notas       string
	}

	http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
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
		}

		if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
			http.Error(w, "Error al renderizar el dashboard", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/inventario", func(w http.ResponseWriter, r *http.Request) {
		flash := r.URL.Query().Get("mensaje")
		products, err := fetchInventoryProducts(db)
		if err != nil {
			http.Error(w, "Error al consultar inventario", http.StatusInternalServerError)
			return
		}
		productsJSON, err := json.Marshal(products)
		if err != nil {
			http.Error(w, "Error al serializar inventario", http.StatusInternalServerError)
			return
		}
		data := inventoryPageData{
			Title:        "Pantalla Inventario (por producto)",
			Subtitle:     "Control por producto con ventas, cambios y auditoría de unidades en FIFO.",
			RoutePrefix:  "",
			Flash:        flash,
			ProductsJSON: template.JS(string(productsJSON)),
		}
		if err := tmpl.ExecuteTemplate(w, "inventario.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/venta/new", func(w http.ResponseWriter, r *http.Request) {
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
		}

		if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/cambio/new", func(w http.ResponseWriter, r *http.Request) {
		productID := r.URL.Query().Get("producto_id")
		cantidad := 1
		if qty := r.URL.Query().Get("cantidad"); qty != "" {
			if parsed, err := strconv.Atoi(qty); err == nil && parsed > 0 {
				cantidad = parsed
			}
		}

		products, err := fetchProductOptions(db)
		if err != nil {
			http.Error(w, "Error al consultar productos", http.StatusInternalServerError)
			return
		}
		if len(products) == 0 {
			http.Error(w, "No hay productos disponibles", http.StatusBadRequest)
			return
		}

		if productID == "" {
			productID = products[0].ID
		}
		selectedProduct, ok := findProduct(products, productID)
		if !ok {
			selectedProduct = products[0]
			productID = selectedProduct.ID
		}

		units, err := fetchAvailableUnits(db, productID)
		if err != nil {
			http.Error(w, "Error al consultar unidades disponibles", http.StatusInternalServerError)
			return
		}
		salientes := make([]string, 0, cantidad)
		for i := 0; i < cantidad && i < len(units); i++ {
			salientes = append(salientes, units[i].ID)
		}

		data := cambioFormData{
			Title:               "Registrar cambio",
			ProductoID:          productID,
			Productos:           products,
			Unidades:            units,
			Salientes:           salientes,
			SalientesMap:        buildSalientesMap(salientes),
			IncomingMode:        "existing",
			IncomingExistingID:  products[0].ID,
			IncomingExistingQty: cantidad,
		}

		if err := tmpl.ExecuteTemplate(w, "cambio_new.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/venta", func(w http.ResponseWriter, r *http.Request) {
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
	})

	http.HandleFunc("/cambio", func(w http.ResponseWriter, r *http.Request) {
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

		selectedProduct, err := fetchProductByID(db, productID)
		if err != nil {
			errors["producto_id"] = "Selecciona un producto válido."
		}

		if personaCambio == "" {
			errors["persona_del_cambio"] = "Ingresa la persona responsable del cambio."
		}

		requestedQty := len(salientes)
		if requestedQty == 0 {
			errors["salientes"] = "Selecciona al menos una unidad disponible como saliente."
		}

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
			if incomingExistingID != "" {
				if _, err := fetchProductByID(db, incomingExistingID); err != nil {
					errors["incoming_existing_id"] = "El producto entrante no existe."
				}
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
			if incomingNewSKU != "" {
				var existingID string
				err := db.QueryRow(`SELECT id FROM productos WHERE id = ?`, incomingNewSKU).Scan(&existingID)
				if err == nil {
					errors["incoming_new_sku"] = "El SKU ya existe como producto."
				} else if err != sql.ErrNoRows {
					http.Error(w, "Error al validar el SKU", http.StatusInternalServerError)
					return
				}
			}
		}

		products, productsErr := fetchProductOptions(db)
		if productsErr != nil {
			http.Error(w, "Error al consultar productos", http.StatusInternalServerError)
			return
		}

		availableUnits, unitsErr := fetchAvailableUnits(db, productID)
		if unitsErr != nil {
			http.Error(w, "Error al consultar unidades disponibles", http.StatusInternalServerError)
			return
		}
		if requestedQty > len(availableUnits) {
			errors["salientes"] = "No puedes cambiar más unidades que el stock disponible."
		}

		if len(errors) > 0 {
			data := cambioFormData{
				Title:               "Registrar cambio",
				ProductoID:          productID,
				Productos:           products,
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

		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "No se pudo registrar el cambio", http.StatusInternalServerError)
			return
		}
		rollback := func() {
			_ = tx.Rollback()
		}

		selectedUnits := []string{}
		rows, err := tx.Query(`SELECT id FROM unidades WHERE producto_id = ? AND estado = 'Disponible' ORDER BY creado_en, id LIMIT ?`, productID, requestedQty)
		if err != nil {
			rollback()
			http.Error(w, "Error al seleccionar unidades disponibles", http.StatusInternalServerError)
			return
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				rollback()
				http.Error(w, "Error al seleccionar unidades disponibles", http.StatusInternalServerError)
				return
			}
			selectedUnits = append(selectedUnits, id)
		}
		rows.Close()
		if len(selectedUnits) != requestedQty {
			rollback()
			http.Error(w, "No hay stock disponible suficiente para el cambio", http.StatusBadRequest)
			return
		}

		placeholders := make([]string, len(selectedUnits))
		args := make([]interface{}, 0, len(selectedUnits))
		for i, id := range selectedUnits {
			placeholders[i] = "?"
			args = append(args, id)
		}
		updateQuery := fmt.Sprintf("UPDATE unidades SET estado = 'Cambio' WHERE id IN (%s)", strings.Join(placeholders, ","))
		if _, err := tx.Exec(updateQuery, args...); err != nil {
			rollback()
			http.Error(w, "No se pudo actualizar unidades salientes", http.StatusInternalServerError)
			return
		}

		entrantes := []string{}
		now := time.Now().Format(time.RFC3339)
		incomingProductID := ""
		if incomingMode == "existing" {
			if _, err := fetchProductByID(db, incomingExistingID); err != nil {
				rollback()
				http.Error(w, "Producto entrante no existe", http.StatusBadRequest)
				return
			}
			incomingProductID = incomingExistingID
			entrantes = buildUnitIDs(fmt.Sprintf("U-%d", time.Now().UnixNano()), incomingExistingQty)
		} else {
			if incomingNewLine == "" {
				incomingNewLine = "Sin línea"
			}
			incomingProductID = incomingNewSKU
			if _, err := tx.Exec(`INSERT INTO productos (id, sku, nombre, linea, precio_base) VALUES (?, ?, ?, ?, ?)`,
				incomingNewSKU, incomingNewSKU, incomingNewName, incomingNewLine, nil); err != nil {
				rollback()
				http.Error(w, "No se pudo crear el producto nuevo", http.StatusInternalServerError)
				return
			}
			entrantes = buildUnitIDs(fmt.Sprintf("U-%d", time.Now().UnixNano()), incomingNewQty)
		}

		for _, unitID := range entrantes {
			if _, err := tx.Exec(`INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES (?, ?, 'Disponible', ?)`,
				unitID, incomingProductID, now); err != nil {
				rollback()
				http.Error(w, "No se pudo registrar las unidades entrantes", http.StatusInternalServerError)
				return
			}
		}

		detalle := map[string]interface{}{
			"mode": incomingMode,
		}
		if incomingMode == "existing" {
			detalle["incoming_product_id"] = incomingExistingID
			detalle["incoming_qty"] = incomingExistingQty
		} else {
			detalle["incoming_new_sku"] = incomingNewSKU
			detalle["incoming_new_name"] = incomingNewName
			detalle["incoming_new_line"] = incomingNewLine
			detalle["incoming_qty"] = incomingNewQty
		}
		unitsJSON, err := json.Marshal(selectedUnits)
		if err != nil {
			rollback()
			http.Error(w, "No se pudo registrar el cambio", http.StatusInternalServerError)
			return
		}
		detalleJSON, err := json.Marshal(detalle)
		if err != nil {
			rollback()
			http.Error(w, "No se pudo registrar el cambio", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec(`INSERT INTO cambios (producto_saliente_id, unidades_ids, persona_cambio, registrado_en, producto_entrante_id, producto_entrante_detalle)
			VALUES (?, ?, ?, ?, ?, ?)`,
			productID, string(unitsJSON), personaCambio, now, incomingProductID, string(detalleJSON)); err != nil {
			rollback()
			http.Error(w, "No se pudo registrar el cambio", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			rollback()
			http.Error(w, "No se pudo confirmar el cambio", http.StatusInternalServerError)
			return
		}

		confirmData := cambioConfirmData{
			Title:               "Cambio registrado",
			ProductoID:          productID,
			ProductoNombre:      selectedProduct.Name,
			PersonaCambio:       personaCambio,
			Notas:               notas,
			Salientes:           selectedUnits,
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
	})

	http.HandleFunc("/csv/template", func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "csv_template.html", struct {
			Title string
		}{
			Title: "Plantilla CSV - Carga masiva",
		}); err != nil {
			http.Error(w, "Error al renderizar plantilla CSV", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/csv/export", func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "csv_export.html", struct {
			Title string
		}{
			Title: "Exportaciones CSV",
		}); err != nil {
			http.Error(w, "Error al renderizar exportaciones CSV", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/inventario", http.StatusFound)
	})

	addr := ":" + port
	log.Printf("Servidor activo en http://localhost:%s/inventario", port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
