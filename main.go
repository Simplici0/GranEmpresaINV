package main

import (
	"database/sql"
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
	Title       string
	Subtitle    string
	RoutePrefix string
	Flash       string
	Products    []inventoryProduct
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
	case "Vendida", "Vendido", "sold":
		return "sold"
	case "Cambio", "swapped":
		return "swapped"
	default:
		return "available"
	}
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
	`

	if _, err := db.Exec(schema); err != nil {
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
		"templates/partials/header.html",
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
		Subtitle    string
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
		Subtitle    string
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
			label := statusLabel(estado)
			estadoConteos = append(estadoConteos, estadoCount{
				Estado:   label,
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
		inventoryProducts := make([]inventoryProduct, 0, len(products))
		for _, product := range products {
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
				} else if estado == "Cambio" || estado == "swapped" {
					changeCount++
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
				if changeCount > 0 {
					estadoLabel = "Cambio"
					estadoClass = "swapped"
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
			Productos:           products,
			Unidades:            availableUnits,
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

		precioFinal, _ := strconv.ParseFloat(precioValue, 64)
		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "Error al procesar la venta", http.StatusInternalServerError)
			return
		}

		_, err = selectAndMarkUnitsSold(tx, productID, cantidad)
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

		if _, err := tx.Exec(
			`INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha)
			VALUES (?, ?, ?, ?, ?, ?)`,
			productID, cantidad, precioFinal, metodoPago, notas, time.Now().Format(time.RFC3339),
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

		selectedProduct, ok := findProduct(products, productID)
		if !ok {
			errors["producto_id"] = "Selecciona un producto válido."
			selectedProduct = products[0]
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
			http.Error(w, "Error al actualizar unidades salientes", http.StatusInternalServerError)
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

		now := time.Now().Format(time.RFC3339)
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
		}

		if err := tmpl.ExecuteTemplate(w, "cambio_confirm.html", confirmData); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/csv/template", func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "csv_template.html", struct {
			Title    string
			Subtitle string
		}{
			Title:    "Plantilla CSV - Carga masiva",
			Subtitle: "",
		}); err != nil {
			http.Error(w, "Error al renderizar plantilla CSV", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/csv/export", func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "csv_export.html", struct {
			Title    string
			Subtitle string
		}{
			Title:    "Exportaciones CSV",
			Subtitle: "",
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
