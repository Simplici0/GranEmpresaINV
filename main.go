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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

type inventoryPageData struct {
	Title       string
	Subtitle    string
	RoutePrefix string
	Flash       string
	MetodoPagos []string
	Products    []inventoryProduct
	CurrentUser *User
}

type unitOption struct {
	ID string
}

type productOption struct {
	ID           string
	Name         string
	Line         string
	FechaIngreso string
	SalePrice    int64
	Units        []unitOption
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
	ID                string
	Name              string
	Line              string
	EstadoLabel       string
	EstadoClass       string
	Disponible        int
	Reservadas        int
	Unidades          []inventoryUnit
	DisabledSale      bool
	FechaIngreso      string
	MesesEnStock      int
	AlertaPermanencia bool
	SalePrice         int64
}

type inventoryCounts struct {
	available   int
	reserved    int
	change      int
	damaged     int
	internalUse int
}

func countInventoryUnits(units []inventoryUnit) inventoryCounts {
	counts := inventoryCounts{}
	for _, unit := range units {
		switch unit.EstadoClass {
		case "available":
			counts.available++
		case "reserved":
			counts.reserved++
		case "swapped":
			counts.change++
		case "damaged":
			counts.damaged++
		case "internal-use":
			counts.internalUse++
		}
	}
	return counts
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
		INSERT INTO productos (sku, id, linea, nombre, fecha_ingreso)
		VALUES (?, ?, ?, ?, COALESCE((SELECT fecha_ingreso FROM productos WHERE sku = ?), CURRENT_TIMESTAMP))
		ON CONFLICT(sku) DO UPDATE SET
			id = excluded.id,
			linea = excluded.linea,
			nombre = excluded.nombre
	`, sku, sku, linea, nombre, sku)
	return err
}

func ensureProductsForUnits(db *sql.DB) error {
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO productos (sku, id, nombre, linea, fecha_ingreso)
		SELECT DISTINCT producto_id, producto_id, producto_id, 'Sin línea', CURRENT_TIMESTAMP
		FROM unidades
	`); err != nil {
		return err
	}
	return nil
}

func seedProductosIfMissing(db *sql.DB, defaults []productOption) error {
	for _, p := range defaults {
		if _, err := db.Exec(`
			INSERT OR IGNORE INTO productos (sku, id, nombre, linea, fecha_ingreso)
			VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		`, p.ID, p.ID, p.Name, p.Line); err != nil {
			return err
		}
	}
	return ensureProductsForUnits(db)
}

func ensureInventoryIntegrityTriggers(exec sqlExecer) error {
	_, err := exec.Exec(`
		CREATE TRIGGER IF NOT EXISTS trg_unidades_producto_insert
		BEFORE INSERT ON unidades
		WHEN NOT EXISTS (SELECT 1 FROM productos WHERE sku = NEW.producto_id OR id = NEW.producto_id)
		BEGIN
			SELECT RAISE(ABORT, 'producto inexistente');
		END;
		CREATE TRIGGER IF NOT EXISTS trg_unidades_producto_update
		BEFORE UPDATE OF producto_id ON unidades
		WHEN NOT EXISTS (SELECT 1 FROM productos WHERE sku = NEW.producto_id OR id = NEW.producto_id)
		BEGIN
			SELECT RAISE(ABORT, 'producto inexistente');
		END;
		CREATE TRIGGER IF NOT EXISTS trg_productos_money_insert
		BEFORE INSERT ON productos
		WHEN NEW.precio_base_cop < 0 OR NEW.precio_venta_cop < 0 OR NEW.precio_consultora_cop < 0
		BEGIN
			SELECT RAISE(ABORT, 'importe COP inválido');
		END;
		CREATE TRIGGER IF NOT EXISTS trg_productos_money_update
		BEFORE UPDATE OF precio_base_cop, precio_venta_cop, precio_consultora_cop ON productos
		WHEN NEW.precio_base_cop < 0 OR NEW.precio_venta_cop < 0 OR NEW.precio_consultora_cop < 0
		BEGIN
			SELECT RAISE(ABORT, 'importe COP inválido');
		END;
		CREATE TRIGGER IF NOT EXISTS trg_ventas_money_insert
		BEFORE INSERT ON ventas
		WHEN NEW.precio_unitario_cop < 0 OR NEW.total_cop < 0
		BEGIN
			SELECT RAISE(ABORT, 'importe COP inválido');
		END;
		CREATE TRIGGER IF NOT EXISTS trg_ventas_money_update
		BEFORE UPDATE OF precio_unitario_cop, total_cop ON ventas
		WHEN NEW.precio_unitario_cop < 0 OR NEW.total_cop < 0
		BEGIN
			SELECT RAISE(ABORT, 'importe COP inválido');
		END;
	`)
	return err
}

func loadProductos(db *sql.DB) ([]productOption, error) {
	rows, err := db.Query(`
		SELECT sku, nombre, linea, COALESCE(fecha_ingreso, ''),
		       CASE WHEN COALESCE(precio_venta_cop, 0) <> 0
		            THEN precio_venta_cop
		            ELSE CAST(ROUND(COALESCE(precio_venta, 0)) AS INTEGER)
		       END
		FROM productos ORDER BY sku`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	products := []productOption{}
	for rows.Next() {
		var p productOption
		if err := rows.Scan(&p.ID, &p.Name, &p.Line, &p.FechaIngreso, &p.SalePrice); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return products, nil
}

func generateNextProductSKU(db *sql.DB) (string, error) {
	rows, err := db.Query(`SELECT sku FROM productos WHERE sku LIKE 'P-%'`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	maxNum := 0
	for rows.Next() {
		var sku string
		if err := rows.Scan(&sku); err != nil {
			return "", err
		}
		if !strings.HasPrefix(sku, "P-") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(sku, "P-"))
		if err != nil {
			continue
		}
		if n > maxNum {
			maxNum = n
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	for next := maxNum + 1; ; next++ {
		candidate := fmt.Sprintf("P-%03d", next)
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = ?`, candidate).Scan(&count); err != nil {
			return "", err
		}
		if count == 0 {
			return candidate, nil
		}
	}
}

func buildLineSuggestions(products []productOption, current string) []string {
	seen := make(map[string]struct{})
	lines := make([]string, 0)
	add := func(raw string) {
		line := strings.TrimSpace(raw)
		if line == "" {
			return
		}
		key := strings.ToLower(line)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		lines = append(lines, line)
	}
	for _, p := range products {
		add(p.Line)
	}
	add(current)
	sort.Slice(lines, func(i, j int) bool {
		return strings.ToLower(lines[i]) < strings.ToLower(lines[j])
	})
	return lines
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

type metodoPagoTotal struct {
	Metodo   string `json:"metodo"`
	Cantidad int    `json:"cantidad"`
	Total    string `json:"total"`
	Value    int64  `json:"value"`
}

type timelinePoint struct {
	Fecha    string `json:"fecha"`
	Cantidad int    `json:"cantidad"`
	Total    string `json:"total"`
	Value    int64  `json:"value"`
}

type dashboardSaleDetail struct {
	ID         int    `json:"id"`
	Fecha      string `json:"fecha"`
	Producto   string `json:"producto"`
	Cantidad   int    `json:"cantidad"`
	Total      string `json:"total"`
	MetodoPago string `json:"metodo_pago"`
	Tipo       string `json:"tipo"`
	EsVenta    bool   `json:"es_venta"`
}

type pieSlice struct {
	Metodo  string  `json:"metodo"`
	Total   string  `json:"total"`
	Percent float64 `json:"percent"`
	Color   string  `json:"color"`
}

type dashboardData struct {
	Title           string
	Subtitle        string
	EstadoConteos   []estadoCount
	MetodosPago     []metodoPagoTotal
	PieSlices       []pieSlice
	PieTotal        string
	MaxTimeline     int64
	MaxTimelineText string
	Timeline        []timelinePoint
	Sales           []dashboardSaleDetail
	CurrentUser     *User
	RangeStart      string
	RangeEnd        string
	RangeTotal      string
	RangeCount      int
}

type dashboardDataResponse struct {
	Ok bool `json:"ok"`

	RangeStart string `json:"range_start"`
	RangeEnd   string `json:"range_end"`
	RangeTotal string `json:"range_total"`
	RangeCount int    `json:"range_count"`

	MetodosPago     []metodoPagoTotal     `json:"metodos_pago"`
	PieSlices       []pieSlice            `json:"pie_slices"`
	PieTotal        string                `json:"pie_total"`
	MaxTimeline     int64                 `json:"max_timeline"`
	MaxTimelineText string                `json:"max_timeline_text"`
	Timeline        []timelinePoint       `json:"timeline"`
	Sales           []dashboardSaleDetail `json:"sales"`
}

func buildDashboardSalesData(db *sql.DB, startStr, endStr string, startDate, endDate time.Time) (dashboardDataResponse, error) {
	resp := dashboardDataResponse{
		Ok:         true,
		RangeStart: startStr,
		RangeEnd:   endStr,
	}

	var rangeTotal int64
	var rangeCount int
	if err := db.QueryRow(`
		SELECT
			COALESCE(SUM(total_cop), 0),
			COALESCE(COUNT(*), 0)
		FROM ventas
		WHERE estado = 'confirmada' AND date(fecha) BETWEEN ? AND ?`, startStr, endStr).Scan(&rangeTotal, &rangeCount); err != nil {
		return dashboardDataResponse{}, err
	}
	resp.RangeTotal = formatCurrency(rangeTotal)
	resp.RangeCount = rangeCount

	metodoRows, err := db.Query(`
		SELECT metodo_pago, COUNT(*), SUM(total_cop)
		FROM ventas
		WHERE estado = 'confirmada' AND date(fecha) BETWEEN ? AND ?
		GROUP BY metodo_pago
		ORDER BY SUM(total_cop) DESC`, startStr, endStr)
	if err != nil {
		return dashboardDataResponse{}, err
	}
	defer metodoRows.Close()

	metodosPago := []metodoPagoTotal{}
	totalPago := int64(0)
	for metodoRows.Next() {
		var metodo string
		var cantidad int
		var total int64
		if err := metodoRows.Scan(&metodo, &cantidad, &total); err != nil {
			return dashboardDataResponse{}, err
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
		return dashboardDataResponse{}, err
	}
	resp.MetodosPago = metodosPago
	resp.PieTotal = formatCurrency(totalPago)

	pieColors := []string{"#2c6bed", "#7d4cf6", "#22a88b", "#f5a524", "#e5484d", "#14b8a6"}
	pieSlices := []pieSlice{}
	for i, metodo := range metodosPago {
		percent := 0.0
		if totalPago > 0 {
			percent = (float64(metodo.Value) / float64(totalPago)) * 100
		}
		color := pieColors[i%len(pieColors)]
		pieSlices = append(pieSlices, pieSlice{
			Metodo:  metodo.Metodo,
			Total:   metodo.Total,
			Percent: percent,
			Color:   color,
		})
	}
	resp.PieSlices = pieSlices

	timeRows, err := db.Query(`
		SELECT date(fecha) as fecha, COUNT(*), SUM(total_cop)
		FROM ventas
		WHERE estado = 'confirmada' AND date(fecha) BETWEEN ? AND ?
		GROUP BY date(fecha)
		ORDER BY date(fecha)`, startStr, endStr)
	if err != nil {
		return dashboardDataResponse{}, err
	}
	defer timeRows.Close()

	timelineByDate := make(map[string]timelinePoint)
	for timeRows.Next() {
		var fecha string
		var cantidad int
		var total int64
		if err := timeRows.Scan(&fecha, &cantidad, &total); err != nil {
			return dashboardDataResponse{}, err
		}
		timelineByDate[fecha] = timelinePoint{
			Fecha:    fecha,
			Cantidad: cantidad,
			Total:    formatCurrency(total),
			Value:    total,
		}
	}
	if err := timeRows.Err(); err != nil {
		return dashboardDataResponse{}, err
	}

	timeline := []timelinePoint{}
	maxTimeline := int64(0)
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
		timeline = append(timeline, point)
		if point.Value > maxTimeline {
			maxTimeline = point.Value
		}
	}

	resp.MaxTimeline = maxTimeline
	resp.MaxTimelineText = formatCurrency(maxTimeline)
	resp.Timeline = timeline

	saleRows, err := db.Query(`
		SELECT
			v.id,
			v.fecha,
			COALESCE(p.nombre, v.producto_id),
			v.cantidad,
			v.total_cop,
			v.metodo_pago
		FROM ventas v
		LEFT JOIN productos p ON p.sku = v.producto_id
		WHERE v.estado = 'confirmada' AND date(v.fecha) BETWEEN ? AND ?
		ORDER BY v.fecha DESC, v.id DESC
	`, startStr, endStr)
	if err != nil {
		return dashboardDataResponse{}, err
	}
	defer saleRows.Close()

	sales := make([]dashboardSaleDetail, 0, 64)
	for saleRows.Next() {
		var (
			id         int
			fechaRaw   string
			producto   string
			cantidad   int
			total      int64
			metodoPago string
		)
		if err := saleRows.Scan(&id, &fechaRaw, &producto, &cantidad, &total, &metodoPago); err != nil {
			return dashboardDataResponse{}, err
		}
		fecha := fechaRaw
		if len(fechaRaw) >= 10 {
			fecha = fechaRaw[:10]
		}
		sales = append(sales, dashboardSaleDetail{
			ID:         id,
			Fecha:      fecha,
			Producto:   producto,
			Cantidad:   cantidad,
			Total:      formatCurrency(total),
			MetodoPago: metodoPago,
			Tipo:       "Venta",
			EsVenta:    true,
		})
	}
	if err := saleRows.Err(); err != nil {
		return dashboardDataResponse{}, err
	}

	internalRows, err := db.Query(`
		SELECT
			MAX(m.id),
			m.fecha,
			COALESCE(p.nombre, m.producto_id),
			COUNT(*),
			COALESCE(m.usuario, ''),
			COALESCE(m.nota, '')
		FROM movimientos m
		LEFT JOIN productos p ON p.sku = m.producto_id
		WHERE m.tipo = 'uso_interno' AND date(m.fecha) BETWEEN ? AND ?
		GROUP BY m.fecha, m.producto_id, COALESCE(p.nombre, m.producto_id), COALESCE(m.usuario, ''), COALESCE(m.nota, '')
	`, startStr, endStr)
	if err != nil {
		return dashboardDataResponse{}, err
	}
	defer internalRows.Close()

	for internalRows.Next() {
		var (
			id       int
			fechaRaw string
			producto string
			cantidad int
			usuario  string
			nota     string
		)
		if err := internalRows.Scan(&id, &fechaRaw, &producto, &cantidad, &usuario, &nota); err != nil {
			return dashboardDataResponse{}, err
		}
		fecha := fechaRaw
		if len(fechaRaw) >= 10 {
			fecha = fechaRaw[:10]
		}
		totalNota := strings.TrimSpace(nota)
		if usuario != "" {
			if totalNota != "" {
				totalNota = fmt.Sprintf("%s | Autorizó: %s", totalNota, usuario)
			} else {
				totalNota = fmt.Sprintf("Autorizó: %s", usuario)
			}
		}
		_ = totalNota
		sales = append(sales, dashboardSaleDetail{
			ID:         id,
			Fecha:      fecha,
			Producto:   producto,
			Cantidad:   cantidad,
			Total:      "-",
			MetodoPago: "Uso interno",
			Tipo:       "Uso interno",
			EsVenta:    false,
		})
	}
	if err := internalRows.Err(); err != nil {
		return dashboardDataResponse{}, err
	}

	sort.SliceStable(sales, func(i, j int) bool {
		if sales[i].Fecha != sales[j].Fecha {
			return sales[i].Fecha > sales[j].Fecha
		}
		return sales[i].ID > sales[j].ID
	})
	resp.Sales = sales

	return resp, nil
}

type User struct {
	ID        int
	Username  string
	Role      string
	IsActive  bool
	CSRFToken string
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
	case "Uso interno", "uso_interno", "internal-use":
		return "internal-use"
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

func ensureAuditEventsTable(exec sqlExecer) error {
	_, err := exec.Exec(`
		CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			entity_type TEXT NOT NULL,
			entity_id TEXT NOT NULL DEFAULT '',
			username TEXT NOT NULL DEFAULT '',
			details TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events (created_at);
		CREATE INDEX IF NOT EXISTS idx_audit_events_entity ON audit_events (entity_type, entity_id);
	`)
	return err
}

func logAudit(tx *sql.Tx, eventType, entityType, entityID, details string, user *User, now string) error {
	username := ""
	if user != nil {
		username = user.Username
	}
	_, err := tx.Exec(`
		INSERT INTO audit_events (event_type, entity_type, entity_id, username, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, eventType, entityType, entityID, username, details, now)
	return err
}

func writeAuditEvent(db *sql.DB, eventType, entityType, entityID, details string, user *User) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := logAudit(tx, eventType, entityType, entityID, details, user, time.Now().Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
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

type saleCancellationError string

func (e saleCancellationError) Error() string { return string(e) }

const (
	errSaleNotFound         saleCancellationError = "venta no encontrada"
	errSaleAlreadyCancelled saleCancellationError = "venta ya anulada"
	errSaleWithoutUnits     saleCancellationError = "venta sin unidades vinculadas"
	errSaleInventoryChanged saleCancellationError = "inventario de venta cambiado"
)

func cancelSale(tx *sql.Tx, saleID int, user *User, reason string) error {
	if user == nil {
		return fmt.Errorf("usuario requerido")
	}
	var productID, state string
	if err := tx.QueryRow(`SELECT producto_id, estado FROM ventas WHERE id = ?`, saleID).Scan(&productID, &state); err != nil {
		if err == sql.ErrNoRows {
			return errSaleNotFound
		}
		return err
	}
	if state != "confirmada" {
		return errSaleAlreadyCancelled
	}

	rows, err := tx.Query(`SELECT unidad_id FROM venta_unidades WHERE venta_id = ? ORDER BY unidad_id`, saleID)
	if err != nil {
		return err
	}
	unitIDs := make([]string, 0)
	for rows.Next() {
		var unitID string
		if err := rows.Scan(&unitID); err != nil {
			rows.Close()
			return err
		}
		unitIDs = append(unitIDs, unitID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(unitIDs) == 0 {
		return errSaleWithoutUnits
	}

	placeholders := make([]string, len(unitIDs))
	args := make([]any, 0, len(unitIDs)+1)
	args = append(args, "Disponible")
	for i, unitID := range unitIDs {
		placeholders[i] = "?"
		args = append(args, unitID)
	}
	query := fmt.Sprintf(
		"UPDATE unidades SET estado = ? WHERE id IN (%s) AND estado IN ('Vendida', 'Vendido', 'sold')",
		strings.Join(placeholders, ","),
	)
	result, err := tx.Exec(query, args...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if int(affected) != len(unitIDs) {
		return errSaleInventoryChanged
	}

	now := time.Now().Format(time.RFC3339)
	if err := logMovimientos(tx, productID, unitIDs, "anulacion_venta", reason, user, now); err != nil {
		return err
	}
	result, err = tx.Exec(`
		UPDATE ventas
		SET estado = 'anulada', anulada_en = ?, anulada_por = ?, anulacion_motivo = ?
		WHERE id = ? AND estado = 'confirmada'
	`, now, user.Username, reason, saleID)
	if err != nil {
		return err
	}
	affected, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errSaleAlreadyCancelled
	}
	if err := logAudit(tx, "sale.cancel", "venta", strconv.Itoa(saleID), reason, user, now); err != nil {
		return err
	}
	return nil
}

func selectAndMarkUnitsSold(tx *sql.Tx, productID string, qty int) ([]string, error) {
	return selectAndMarkUnitsByStatus(tx, productID, qty, "Vendida")
}

func selectAndMarkSpecificUnits(tx *sql.Tx, productID string, unitIDs []string, nextStatus string) ([]string, error) {
	if strings.TrimSpace(productID) == "" || len(unitIDs) == 0 {
		return nil, fmt.Errorf("unidades inválidas")
	}

	seen := make(map[string]struct{}, len(unitIDs))
	for _, id := range unitIDs {
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("unidad inválida")
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("unidad repetida")
		}
		seen[id] = struct{}{}
	}

	placeholders := make([]string, len(unitIDs))
	args := make([]any, 0, len(unitIDs)+2)
	args = append(args, nextStatus, productID)
	for i, id := range unitIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	query := fmt.Sprintf(`
		UPDATE unidades
		SET estado = ?
		WHERE producto_id = ?
		  AND id IN (%s)
		  AND estado IN ('Disponible', 'available')`, strings.Join(placeholders, ","))
	result, err := tx.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("update unidades seleccionadas: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("rows affected: %w", err)
	}
	if int(affected) != len(unitIDs) {
		return nil, errInsufficientStock
	}

	return append([]string(nil), unitIDs...), nil
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

func availableCountsByProduct(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query(`
		SELECT producto_id, COUNT(*)
		FROM unidades
		WHERE estado IN ('Disponible', 'available')
		GROUP BY producto_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var id string
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		out[id] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func formatCurrency(value int64) string {
	return "$" + formatIntDots(value)
}

// formatIntDots formats an integer with '.' as thousands separator (e.g. 1234567 -> "1.234.567").
// This matches common Spanish formatting and improves readability in UI.
func formatIntDots(n int64) string {
	if n == 0 {
		return "0"
	}
	sign := ""
	if n < 0 {
		sign = "-"
		n = -n
	}

	s := strconv.FormatInt(n, 10)
	// Insert '.' every 3 digits from the right.
	out := make([]byte, 0, len(s)+len(s)/3)
	rem := len(s) % 3
	if rem == 0 {
		rem = 3
	}
	out = append(out, s[:rem]...)
	for i := rem; i < len(s); i += 3 {
		out = append(out, '.')
		out = append(out, s[i:i+3]...)
	}
	return sign + string(out)
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

// parseCOPInteger parses a currency-like string into an integer COP value.
// It accepts plain numbers and formatted inputs (e.g. "1.234.567", "$1,234,567").
func parseCOPInteger(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty")
	}
	clean := strings.ReplaceAll(raw, "$", "")
	clean = strings.ReplaceAll(clean, " ", "")
	if clean == "" || strings.HasPrefix(clean, "-") {
		return 0, fmt.Errorf("invalid")
	}
	clean = strings.TrimPrefix(clean, "+")
	if clean == "" {
		return 0, fmt.Errorf("invalid")
	}
	parts := strings.FieldsFunc(clean, func(r rune) bool { return r == '.' || r == ',' })
	if strings.ContainsAny(clean, ".,") {
		if len(parts) < 2 || len(parts[0]) < 1 || len(parts[0]) > 3 {
			return 0, fmt.Errorf("invalid")
		}
		for i, part := range parts {
			if i > 0 && len(part) != 3 {
				return 0, fmt.Errorf("invalid")
			}
		}
		clean = strings.Join(parts, "")
	}
	for _, r := range clean {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid")
		}
	}
	v, err := strconv.Atoi(clean)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func parseFlexibleTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	// Common formats used in this app/SQLite:
	// - RFC3339 for movimiento/unidad timestamps
	// - "YYYY-MM-DD HH:MM:SS" for SQLite CURRENT_TIMESTAMP
	// - "YYYY-MM-DD" for date-only values
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// monthsBetween returns the number of full months elapsed from start to end.
func monthsBetween(start, end time.Time) int {
	start = time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)
	end = time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC)
	if end.Before(start) {
		start, end = end, start
	}
	months := int(end.Year()-start.Year())*12 + int(end.Month()-start.Month())
	// If we haven't reached the "day of month" yet, subtract a month.
	if end.Day() < start.Day() {
		months--
	}
	if months < 0 {
		return 0
	}
	return months
}

func statusLabel(estado string) string {
	labels := map[string]string{
		"available":    "Disponible",
		"sold":         "Vendido",
		"swapped":      "Cambio",
		"internal-use": "Uso interno",
		"Disponible":   "Disponible",
		"Vendida":      "Vendido",
		"Vendido":      "Vendido",
		"Cambio":       "Cambio",
		"Uso interno":  "Uso interno",
		"uso_interno":  "Uso interno",
	}
	if label, ok := labels[estado]; ok {
		return label
	}
	return estado
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
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
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
		csrfToken  string
		expiresRaw string
	)
	query := `
		SELECT u.id, u.username, u.role, u.is_active, s.csrf_token, s.expires_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token = ?`
	if err := db.QueryRow(query, cookie.Value).Scan(&user.ID, &user.Username, &user.Role, &isActive, &csrfToken, &expiresRaw); err != nil {
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
	if csrfToken == "" {
		csrfToken, err = generateToken()
		if err != nil {
			return nil, err
		}
		if _, err := db.Exec("UPDATE sessions SET csrf_token = ? WHERE token = ?", csrfToken, cookie.Value); err != nil {
			return nil, err
		}
	}
	user.CSRFToken = csrfToken
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

func redirectWithMessage(w http.ResponseWriter, r *http.Request, path, message, errMsg string) {
	params := url.Values{}
	if message != "" {
		params.Set("mensaje", message)
	}
	if errMsg != "" {
		params.Set("error", errMsg)
	}
	target := path
	if encoded := params.Encode(); encoded != "" {
		target = target + "?" + encoded
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func userCreateErrorText(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "UNIQUE constraint failed: users.username"):
		return "El usuario ya existe."
	case strings.Contains(msg, "CHECK constraint failed"):
		return "Datos inválidos (revisa el rol)."
	case strings.Contains(msg, "database is locked"):
		return "La base de datos está ocupada. Intenta de nuevo."
	default:
		return "No se pudo crear el usuario."
	}
}

func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	// SQLite PRAGMA table_info does not reliably accept a bound parameter for table name,
	// so we build the statement after validating the identifier.
	if !validSQLiteIdentifier(table) {
		return nil, fmt.Errorf("invalid table name: %q", table)
	}
	rows, err := db.Query(fmt.Sprintf("SELECT name FROM pragma_table_info('%s')", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cols, nil
}

func validSQLiteIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func ensureSQLiteColumnTx(tx *sql.Tx, table, column, definition string) error {
	if !validSQLiteIdentifier(table) || !validSQLiteIdentifier(column) {
		return fmt.Errorf("invalid SQLite column target: %s.%s", table, column)
	}
	var exists int
	if err := tx.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name = ?", table),
		column,
	).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	_, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	return err
}

func ensureSchemaMigrations(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)
	`)
	return err
}

func applySchemaMigration(db *sql.DB, version int, migrate func(*sql.Tx) error) error {
	var applied int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&applied); err != nil {
		return err
	}
	if applied > 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := migrate(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, version, time.Now().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func migrateLegacySchema(tx *sql.Tx) error {
	if err := ensureSQLiteColumnTx(tx, "productos", "id", "TEXT"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE productos SET id = sku WHERE id IS NULL OR id = ''"); err != nil {
		return err
	}
	if _, err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_productos_id_unique ON productos(id)"); err != nil {
		return err
	}
	if err := ensureSQLiteColumnTx(tx, "productos", "fecha_ingreso", "TEXT"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE productos SET fecha_ingreso = CURRENT_TIMESTAMP WHERE fecha_ingreso IS NULL OR fecha_ingreso = ''"); err != nil {
		return err
	}
	if err := ensureSQLiteColumnTx(tx, "ventas", "notas", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureSQLiteColumnTx(tx, "unidades", "caducidad", "TEXT"); err != nil {
		return err
	}
	if err := ensureSQLiteColumnTx(tx, "sessions", "csrf_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return nil
}

func migrateSalesSchema(tx *sql.Tx) error {
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "estado", definition: "TEXT NOT NULL DEFAULT 'confirmada'"},
		{name: "anulada_en", definition: "TEXT"},
		{name: "anulada_por", definition: "TEXT"},
		{name: "anulacion_motivo", definition: "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := ensureSQLiteColumnTx(tx, "ventas", column.name, column.definition); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_ventas_estado_fecha ON ventas (estado, fecha);
		CREATE TABLE IF NOT EXISTS venta_unidades (
			venta_id INTEGER NOT NULL,
			unidad_id TEXT NOT NULL,
			PRIMARY KEY (venta_id, unidad_id),
			UNIQUE (unidad_id),
			FOREIGN KEY (venta_id) REFERENCES ventas (id) ON DELETE CASCADE,
			FOREIGN KEY (unidad_id) REFERENCES unidades (id) ON DELETE RESTRICT
		);
		CREATE INDEX IF NOT EXISTS idx_venta_unidades_unidad ON venta_unidades (unidad_id);
	`); err != nil {
		return err
	}
	return nil
}

func migrateMoneySchema(tx *sql.Tx) error {
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "precio_base_cop", definition: "INTEGER NOT NULL DEFAULT 0"},
		{name: "precio_venta_cop", definition: "INTEGER NOT NULL DEFAULT 0"},
		{name: "precio_consultora_cop", definition: "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := ensureSQLiteColumnTx(tx, "productos", column.name, column.definition); err != nil {
			return err
		}
	}
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "precio_unitario_cop", definition: "INTEGER NOT NULL DEFAULT 0"},
		{name: "total_cop", definition: "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := ensureSQLiteColumnTx(tx, "ventas", column.name, column.definition); err != nil {
			return err
		}
	}
	var invalidPrices int
	if err := tx.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM productos WHERE COALESCE(precio_base, 0) < 0 OR COALESCE(precio_venta, 0) < 0 OR COALESCE(precio_consultora, 0) < 0) +
			(SELECT COUNT(*) FROM ventas WHERE COALESCE(precio_final, 0) < 0)
	`).Scan(&invalidPrices); err != nil {
		return err
	}
	if invalidPrices > 0 {
		return fmt.Errorf("la base contiene %d importes negativos", invalidPrices)
	}
	updates := []string{
		"UPDATE productos SET precio_base_cop = CAST(ROUND(COALESCE(precio_base, 0)) AS INTEGER) WHERE precio_base_cop = 0 AND COALESCE(precio_base, 0) <> 0",
		"UPDATE productos SET precio_venta_cop = CAST(ROUND(COALESCE(precio_venta, 0)) AS INTEGER) WHERE precio_venta_cop = 0 AND COALESCE(precio_venta, 0) <> 0",
		"UPDATE productos SET precio_consultora_cop = CAST(ROUND(COALESCE(precio_consultora, 0)) AS INTEGER) WHERE precio_consultora_cop = 0 AND COALESCE(precio_consultora, 0) <> 0",
		"UPDATE ventas SET precio_unitario_cop = CAST(ROUND(COALESCE(precio_final, 0)) AS INTEGER) WHERE precio_unitario_cop = 0 AND COALESCE(precio_final, 0) <> 0",
		"UPDATE ventas SET total_cop = CAST(ROUND(COALESCE(precio_final, 0) * cantidad) AS INTEGER) WHERE total_cop = 0 AND COALESCE(precio_final, 0) <> 0",
	}
	for _, query := range updates {
		if _, err := tx.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func migrateAuditSchema(tx *sql.Tx) error {
	return ensureAuditEventsTable(tx)
}

func migrateIntegritySchema(tx *sql.Tx) error {
	return ensureInventoryIntegrityTriggers(tx)
}

func demoSeedEnabled(db *sql.DB) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("SEED_DEMO")))
	if raw != "1" && raw != "true" && raw != "yes" && raw != "on" {
		return false
	}
	return !demoSeedDisabled(db)
}

func ensureAppMetaTable(exec sqlExecer) error {
	_, err := exec.Exec(`
		CREATE TABLE IF NOT EXISTS app_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)
	`)
	return err
}

func demoSeedDisabled(db *sql.DB) bool {
	var value string
	if err := db.QueryRow(`SELECT value FROM app_meta WHERE key = 'demo_seed_disabled'`).Scan(&value); err != nil {
		return false
	}
	return value == "1"
}

func initDB(path string, paymentMethods []string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
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
		precio_base_cop INTEGER NOT NULL DEFAULT 0,
		precio_venta_cop INTEGER NOT NULL DEFAULT 0,
		precio_consultora_cop INTEGER NOT NULL DEFAULT 0,
		descuento REAL NOT NULL DEFAULT 0,
		anotaciones TEXT NOT NULL DEFAULT '',
		aplica_caducidad INTEGER NOT NULL DEFAULT 0,
		fecha_ingreso TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
	);
	CREATE INDEX IF NOT EXISTS idx_productos_linea ON productos (linea);

	CREATE TABLE IF NOT EXISTS ventas (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		producto_id TEXT NOT NULL,
		cantidad INTEGER NOT NULL,
		precio_final REAL NOT NULL,
		metodo_pago TEXT NOT NULL,
		notas TEXT NOT NULL DEFAULT '',
		fecha TEXT NOT NULL,
		precio_unitario_cop INTEGER NOT NULL DEFAULT 0,
		total_cop INTEGER NOT NULL DEFAULT 0,
		estado TEXT NOT NULL DEFAULT 'confirmada',
		anulada_en TEXT,
		anulada_por TEXT,
		anulacion_motivo TEXT NOT NULL DEFAULT ''
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
		csrf_token TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS venta_unidades (
		venta_id INTEGER NOT NULL,
		unidad_id TEXT NOT NULL,
		PRIMARY KEY (venta_id, unidad_id),
		UNIQUE (unidad_id),
		FOREIGN KEY (venta_id) REFERENCES ventas (id) ON DELETE CASCADE,
		FOREIGN KEY (unidad_id) REFERENCES unidades (id) ON DELETE RESTRICT
	);
	`

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	if err := ensureAppMetaTable(db); err != nil {
		return nil, err
	}

	if err := ensureMovimientosTable(db); err != nil {
		return nil, err
	}
	if err := ensureSchemaMigrations(db); err != nil {
		return nil, err
	}
	if err := applySchemaMigration(db, 1, migrateLegacySchema); err != nil {
		return nil, err
	}
	if err := applySchemaMigration(db, 2, migrateSalesSchema); err != nil {
		return nil, err
	}
	if err := applySchemaMigration(db, 3, migrateMoneySchema); err != nil {
		return nil, err
	}
	if err := applySchemaMigration(db, 4, migrateAuditSchema); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, err
	}
	_, _ = db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Format(time.RFC3339))

	seedDemoData := demoSeedEnabled(db)
	if seedDemoData {
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
	}
	if err := applySchemaMigration(db, 5, migrateIntegritySchema); err != nil {
		return nil, err
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
	stmt, err := tx.Prepare(`INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
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
			precio := int64(18000 + (i * 1200) + (j * 800))
			metodo := paymentMethods[(i+j)%len(paymentMethods)]
			if _, err := stmt.Exec(productoID, cantidad, float64(precio), metodo, "Venta seed", date, precio, precio*int64(cantidad)); err != nil {
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

func insertSeedAdminUser(tx *sql.Tx) error {
	adminUser := strings.TrimSpace(os.Getenv("ADMIN_USER"))
	adminPass := os.Getenv("ADMIN_PASS")
	if adminUser == "" || adminPass == "" {
		return fmt.Errorf("ADMIN_USER y ADMIN_PASS deben estar configurados para ejecutar este reset")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	cols, err := tableColumnsTx(tx, "users")
	if err != nil {
		return err
	}

	insertCols := []string{"username", "password_hash", "role", "created_at"}
	args := []any{adminUser, string(hashed), "admin", time.Now().Format(time.RFC3339)}
	if cols["is_active"] {
		insertCols = append(insertCols, "is_active")
		args = append(args, 1)
	}
	if cols["active"] {
		insertCols = append(insertCols, "active")
		args = append(args, 1)
	}
	if cols["name"] {
		insertCols = append(insertCols, "name")
		args = append(args, adminUser)
	}
	if cols["email"] {
		insertCols = append(insertCols, "email")
		args = append(args, adminUser+"@local")
	}

	placeholders := make([]string, len(insertCols))
	for i := range placeholders {
		placeholders[i] = "?"
	}
	_, err = tx.Exec(
		fmt.Sprintf("INSERT INTO users (%s) VALUES (%s)", strings.Join(insertCols, ", "), strings.Join(placeholders, ", ")),
		args...,
	)
	return err
}

func tableColumnsTx(tx *sql.Tx, table string) (map[string]bool, error) {
	if !validSQLiteIdentifier(table) {
		return nil, fmt.Errorf("invalid table name: %q", table)
	}
	rows, err := tx.Query(fmt.Sprintf("SELECT name FROM pragma_table_info('%s')", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cols, nil
}

func tableExistsTx(tx *sql.Tx, table string) (bool, error) {
	if !validSQLiteIdentifier(table) {
		return false, fmt.Errorf("invalid table name: %q", table)
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func deleteTableIfExists(tx *sql.Tx, table string) error {
	exists, err := tableExistsTx(tx, table)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	_, err = tx.Exec(fmt.Sprintf("DELETE FROM %s", table))
	return err
}

func resetSQLiteSequences(tx *sql.Tx, tables []string) error {
	exists, err := tableExistsTx(tx, "sqlite_sequence")
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	for _, table := range tables {
		if !validSQLiteIdentifier(table) {
			return fmt.Errorf("invalid table name: %q", table)
		}
		if _, err := tx.Exec(`DELETE FROM sqlite_sequence WHERE name = ?`, table); err != nil {
			return err
		}
	}
	return nil
}

func resetBusinessData(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := ensureAppMetaTable(tx); err != nil {
		return err
	}

	tables := []string{
		"invoice_items",
		"invoices",
		"product_loan_units",
		"product_loans",
		"credit_installments",
		"credit_sales",
		"customer_events",
		"customers",
		"cambios",
		"retomas",
		"movimientos",
		"ventas",
		"unidades",
		"precio_venta_historial",
		"productos",
	}
	for _, table := range tables {
		if err := deleteTableIfExists(tx, table); err != nil {
			return fmt.Errorf("reset %s: %w", table, err)
		}
	}
	if err := resetSQLiteSequences(tx, tables); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO app_meta (key, value)
		VALUES ('demo_seed_disabled', '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func resetUsersData(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := deleteTableIfExists(tx, "sessions"); err != nil {
		return err
	}
	if err := deleteTableIfExists(tx, "users"); err != nil {
		return err
	}
	if err := resetSQLiteSequences(tx, []string{"users"}); err != nil {
		return err
	}
	if err := insertSeedAdminUser(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
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
		"templates/admin_settings.html",
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
	loginLimiter := newLoginRateLimiter()

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
	if demoSeedEnabled(db) {
		if err := seedProductosIfMissing(db, defaultProducts); err != nil {
			log.Fatalf("Error al seed de productos: %v", err)
		}
	} else if err := ensureProductsForUnits(db); err != nil {
		log.Fatalf("Error al alinear productos con unidades: %v", err)
	}
	if _, err := loadProductos(db); err != nil {
		log.Fatalf("Error al cargar productos: %v", err)
	}

	usersCols, err := tableColumns(db, "users")
	if err != nil {
		log.Fatalf("Error al leer esquema de users: %v", err)
	}

	type ventaFormData struct {
		Title           string
		Subtitle        string
		ProductoID      string
		ProductoNom     string
		Productos       []productOption
		StockByProd     map[string]int
		Cantidad        int
		PrecioFinal     string
		ValorVentaFinal string
		MetodoPago      string
		Notas           string
		Errors          map[string]string
		MetodoPagos     []string
		RoutePrefix     string
		CurrentUser     *User
	}

	type ventaConfirmData struct {
		Title           string
		Subtitle        string
		ProductoID      string
		ProductoNom     string
		Cantidad        int
		PrecioFinal     string
		ValorVentaFinal string
		MetodoPago      string
		Notas           string
		CurrentUser     *User
	}

	type loginPageData struct {
		Title    string
		Error    string
		Username string
	}

	type adminUserRow struct {
		ID        int
		Username  string
		Name      string
		Email     string
		Role      string
		IsActive  bool
		CreatedAt string
	}

	type adminUsersData struct {
		Title       string
		Subtitle    string
		Flash       string
		Error       string
		Users       []adminUserRow
		CurrentUser *User
	}

	type adminSettingsData struct {
		Title       string
		Subtitle    string
		Flash       string
		Error       string
		CurrentUser *User
	}

	type productNewData struct {
		Title       string
		Subtitle    string
		Flash       string
		SKU         string
		Nombre      string
		Linea       string
		PrecioVenta string
		Lineas      []string
		Cantidad    int
		AplicaCad   bool
		Caducidad   string
		Errors      map[string]string
		CurrentUser *User
	}

	mux := http.NewServeMux()

	// Serve static assets from ./static at /static/.
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/favicon.svg")
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var one int
		if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
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
		rateKey := loginRateLimitKey(r, username)
		if allowed, retryAfter := loginLimiter.allow(rateKey); !allowed {
			seconds := int(retryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			data := loginPageData{
				Title:    "Iniciar sesión",
				Error:    "Demasiados intentos. Intenta de nuevo más tarde.",
				Username: username,
			}
			w.WriteHeader(http.StatusTooManyRequests)
			if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
				http.Error(w, "Error al renderizar login", http.StatusInternalServerError)
			}
			return
		}

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
			loginLimiter.recordFailure(rateKey)
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
			loginLimiter.recordFailure(rateKey)
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
		csrfToken, err := generateToken()
		if err != nil {
			http.Error(w, "No se pudo generar protección CSRF", http.StatusInternalServerError)
			return
		}
		expiresAt := time.Now().Add(24 * time.Hour)
		_, err = db.Exec(`
			INSERT INTO sessions (token, user_id, csrf_token, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?)
		`, token, user.ID, csrfToken, time.Now().Format(time.RFC3339), expiresAt.Format(time.RFC3339))
		if err != nil {
			http.Error(w, "No se pudo guardar la sesión", http.StatusInternalServerError)
			return
		}

		loginLimiter.recordSuccess(rateKey)
		setSessionCookie(w, token, expiresAt, sessionCookieSecure())
		http.Redirect(w, r, "/inventario", http.StatusSeeOther)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
			return
		}
		if cookie, err := r.Cookie("session_token"); err == nil {
			_, _ = db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
		}
		clearSessionCookie(w, sessionCookieSecure())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	mux.HandleFunc("/admin/users", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		flash := r.URL.Query().Get("mensaje")
		errText := r.URL.Query().Get("error")

		// Support legacy schemas by selecting optional columns if they exist.
		selectCols := []string{"id", "username"}
		if usersCols["name"] {
			selectCols = append(selectCols, "name")
		} else {
			selectCols = append(selectCols, "'' as name")
		}
		if usersCols["email"] {
			selectCols = append(selectCols, "email")
		} else {
			selectCols = append(selectCols, "'' as email")
		}
		selectCols = append(selectCols, "role")
		if usersCols["is_active"] {
			selectCols = append(selectCols, "is_active")
		} else if usersCols["active"] {
			selectCols = append(selectCols, "active as is_active")
		} else {
			selectCols = append(selectCols, "1 as is_active")
		}
		if usersCols["created_at"] {
			selectCols = append(selectCols, "created_at")
		} else {
			selectCols = append(selectCols, "'' as created_at")
		}

		rows, err := db.Query(fmt.Sprintf("SELECT %s FROM users ORDER BY id", strings.Join(selectCols, ", ")))
		if err != nil {
			http.Error(w, "Error al consultar usuarios", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		users := []adminUserRow{}
		for rows.Next() {
			var user adminUserRow
			var isActive int
			var username sql.NullString
			var name sql.NullString
			var email sql.NullString
			if err := rows.Scan(&user.ID, &username, &name, &email, &user.Role, &isActive, &user.CreatedAt); err != nil {
				http.Error(w, "Error al leer usuarios", http.StatusInternalServerError)
				return
			}
			user.Username = username.String
			user.Name = name.String
			user.Email = email.String
			user.IsActive = isActive == 1
			users = append(users, user)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "Error al procesar usuarios", http.StatusInternalServerError)
			return
		}

		data := adminUsersData{
			Title:       "Roles de usuario",
			Subtitle:    "Control de accesos y roles del inventario.",
			Flash:       flash,
			Error:       errText,
			Users:       users,
			CurrentUser: userFromContext(r),
		}
		if err := tmpl.ExecuteTemplate(w, "admin_users.html", data); err != nil {
			http.Error(w, "Error al renderizar usuarios", http.StatusInternalServerError)
		}
	}))

	mux.HandleFunc("/admin/users/create", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			redirectWithMessage(w, r, "/admin/users", "", "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo leer el formulario.")
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		name := strings.TrimSpace(r.FormValue("name"))
		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		role := strings.TrimSpace(r.FormValue("role"))
		isActive := r.FormValue("is_active") != ""

		if username == "" {
			redirectWithMessage(w, r, "/admin/users", "", "Usuario obligatorio.")
			return
		}
		if password == "" {
			redirectWithMessage(w, r, "/admin/users", "", "Contraseña obligatoria.")
			return
		}
		if len(password) < 8 {
			redirectWithMessage(w, r, "/admin/users", "", "La contraseña debe tener al menos 8 caracteres.")
			return
		}
		if role != "admin" && role != "empleado" {
			redirectWithMessage(w, r, "/admin/users", "", "Rol inválido.")
			return
		}

		if usersCols["name"] && name == "" {
			name = username
		}
		if usersCols["email"] && email == "" {
			// If username already looks like an email, reuse it.
			if strings.Contains(username, "@") {
				email = username
			} else {
				email = username + "@local"
			}
		}
		if usersCols["email"] {
			var emailExists int
			if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = ?`, email).Scan(&emailExists); err == nil && emailExists > 0 {
				redirectWithMessage(w, r, "/admin/users", "", "El email ya existe.")
				return
			}
		}

		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, username).Scan(&exists); err == nil && exists > 0 {
			redirectWithMessage(w, r, "/admin/users", "", "El usuario ya existe.")
			return
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo procesar la contraseña.")
			return
		}

		activeInt := 0
		if isActive {
			activeInt = 1
		}

		cols := []string{"username", "password_hash", "role"}
		args := []any{username, string(hashed), role}
		if usersCols["name"] {
			cols = append(cols, "name")
			args = append(args, name)
		}
		if usersCols["email"] {
			cols = append(cols, "email")
			args = append(args, email)
		}
		if usersCols["password_salt"] {
			cols = append(cols, "password_salt")
			args = append(args, "bcrypt")
		}
		if usersCols["created_at"] {
			cols = append(cols, "created_at")
			args = append(args, time.Now().Format(time.RFC3339))
		}
		if usersCols["is_active"] {
			cols = append(cols, "is_active")
			args = append(args, activeInt)
		}
		if usersCols["active"] {
			cols = append(cols, "active")
			args = append(args, activeInt)
		}

		placeholders := make([]string, len(cols))
		for i := range placeholders {
			placeholders[i] = "?"
		}

		_, err = db.Exec(
			fmt.Sprintf("INSERT INTO users (%s) VALUES (%s)", strings.Join(cols, ", "), strings.Join(placeholders, ", ")),
			args...,
		)
		if err != nil {
			log.Printf("admin/users/create: insert failed username=%q err=%v", username, err)
			redirectWithMessage(w, r, "/admin/users", "", userCreateErrorText(err))
			return
		}
		if err := writeAuditEvent(db, "user.create", "user", username, "role="+role, userFromContext(r)); err != nil {
			log.Printf("admin/users/create: audit failed username=%q err=%v", username, err)
		}

		redirectWithMessage(w, r, "/admin/users", "Usuario creado.", "")
	}))

	mux.HandleFunc("/admin/users/update", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			redirectWithMessage(w, r, "/admin/users", "", "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo leer el formulario.")
			return
		}

		idValue := strings.TrimSpace(r.FormValue("id"))
		userID, err := strconv.Atoi(idValue)
		if err != nil || userID <= 0 {
			redirectWithMessage(w, r, "/admin/users", "", "ID inválido.")
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		name := strings.TrimSpace(r.FormValue("name"))
		email := strings.TrimSpace(r.FormValue("email"))
		role := strings.TrimSpace(r.FormValue("role"))
		isActive := r.FormValue("is_active") != ""

		if username == "" {
			redirectWithMessage(w, r, "/admin/users", "", "Usuario obligatorio.")
			return
		}
		if role != "admin" && role != "empleado" {
			redirectWithMessage(w, r, "/admin/users", "", "Rol inválido.")
			return
		}
		if usersCols["name"] && name == "" {
			name = username
		}
		if usersCols["email"] && email == "" {
			if strings.Contains(username, "@") {
				email = username
			} else {
				email = username + "@local"
			}
		}

		// Prevent leaving the system without any active admin.
		var currentRole string
		var currentActive int
		if err := db.QueryRow(`SELECT role, is_active FROM users WHERE id = ?`, userID).Scan(&currentRole, &currentActive); err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "Usuario no encontrado.")
			return
		}
		willBeActive := 0
		if isActive {
			willBeActive = 1
		}
		isDemotingAdmin := currentRole == "admin" && role != "admin" && currentActive == 1
		isDeactivatingAdmin := currentRole == "admin" && currentActive == 1 && willBeActive == 0
		if isDemotingAdmin || isDeactivatingAdmin {
			var otherActiveAdmins int
			if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1 AND id != ?`, userID).Scan(&otherActiveAdmins); err == nil {
				if otherActiveAdmins == 0 {
					redirectWithMessage(w, r, "/admin/users", "", "Debe existir al menos un admin activo.")
					return
				}
			}
		}

		setCols := []string{"username = ?", "role = ?"}
		args := []any{username, role}
		if usersCols["name"] {
			setCols = append(setCols, "name = ?")
			args = append(args, name)
		}
		if usersCols["email"] {
			setCols = append(setCols, "email = ?")
			args = append(args, email)
		}
		if usersCols["is_active"] {
			setCols = append(setCols, "is_active = ?")
			args = append(args, willBeActive)
		}
		if usersCols["active"] {
			setCols = append(setCols, "active = ?")
			args = append(args, willBeActive)
		}
		args = append(args, userID)

		_, err = db.Exec(fmt.Sprintf("UPDATE users SET %s WHERE id = ?", strings.Join(setCols, ", ")), args...)
		if err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo actualizar el usuario.")
			return
		}

		// If deactivated, invalidate sessions.
		if willBeActive == 0 {
			_, _ = db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
		}
		if err := writeAuditEvent(db, "user.update", "user", strconv.Itoa(userID), "role="+role, userFromContext(r)); err != nil {
			log.Printf("admin/users/update: audit failed user_id=%d err=%v", userID, err)
		}

		redirectWithMessage(w, r, "/admin/users", "Usuario actualizado.", "")
	}))

	mux.HandleFunc("/admin/users/password", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			redirectWithMessage(w, r, "/admin/users", "", "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo leer el formulario.")
			return
		}

		idValue := strings.TrimSpace(r.FormValue("id"))
		userID, err := strconv.Atoi(idValue)
		if err != nil || userID <= 0 {
			redirectWithMessage(w, r, "/admin/users", "", "ID inválido.")
			return
		}
		password := r.FormValue("password")
		if password == "" {
			redirectWithMessage(w, r, "/admin/users", "", "Contraseña obligatoria.")
			return
		}
		if len(password) < 8 {
			redirectWithMessage(w, r, "/admin/users", "", "La contraseña debe tener al menos 8 caracteres.")
			return
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo procesar la contraseña.")
			return
		}

		setCols := []string{"password_hash = ?"}
		args := []any{string(hashed)}
		if usersCols["password_salt"] {
			setCols = append(setCols, "password_salt = ?")
			args = append(args, "bcrypt")
		}
		args = append(args, userID)
		if _, err := db.Exec(fmt.Sprintf("UPDATE users SET %s WHERE id = ?", strings.Join(setCols, ", ")), args...); err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo actualizar la contraseña.")
			return
		}
		_, _ = db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
		if err := writeAuditEvent(db, "user.password_change", "user", strconv.Itoa(userID), "", userFromContext(r)); err != nil {
			log.Printf("admin/users/password: audit failed user_id=%d err=%v", userID, err)
		}
		redirectWithMessage(w, r, "/admin/users", "Contraseña actualizada (sesiones cerradas).", "")
	}))

	mux.HandleFunc("/admin/users/delete", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			redirectWithMessage(w, r, "/admin/users", "", "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo leer el formulario.")
			return
		}

		idValue := strings.TrimSpace(r.FormValue("id"))
		userID, err := strconv.Atoi(idValue)
		if err != nil || userID <= 0 {
			redirectWithMessage(w, r, "/admin/users", "", "ID inválido.")
			return
		}
		current := userFromContext(r)
		if current != nil && current.ID == userID {
			redirectWithMessage(w, r, "/admin/users", "", "No puedes eliminar tu propio usuario.")
			return
		}

		var role string
		var isActive int
		if err := db.QueryRow(`SELECT role, is_active FROM users WHERE id = ?`, userID).Scan(&role, &isActive); err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "Usuario no encontrado.")
			return
		}
		if role == "admin" && isActive == 1 {
			var otherActiveAdmins int
			if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1 AND id != ?`, userID).Scan(&otherActiveAdmins); err == nil {
				if otherActiveAdmins == 0 {
					redirectWithMessage(w, r, "/admin/users", "", "No puedes eliminar el último admin activo.")
					return
				}
			}
		}

		_, _ = db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
		if _, err := db.Exec(`DELETE FROM users WHERE id = ?`, userID); err != nil {
			redirectWithMessage(w, r, "/admin/users", "", "No se pudo eliminar el usuario.")
			return
		}
		if err := writeAuditEvent(db, "user.delete", "user", strconv.Itoa(userID), "", current); err != nil {
			log.Printf("admin/users/delete: audit failed user_id=%d err=%v", userID, err)
		}

		redirectWithMessage(w, r, "/admin/users", "Usuario eliminado.", "")
	}))

	mux.HandleFunc("/admin/settings", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		data := adminSettingsData{
			Title:       "Configuración",
			Subtitle:    "Herramientas administrativas críticas.",
			Flash:       r.URL.Query().Get("mensaje"),
			Error:       r.URL.Query().Get("error"),
			CurrentUser: userFromContext(r),
		}
		if err := tmpl.ExecuteTemplate(w, "admin_settings.html", data); err != nil {
			http.Error(w, "Error al renderizar configuración", http.StatusInternalServerError)
		}
	}))

	mux.HandleFunc("/admin/settings/reset-users", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			redirectWithMessage(w, r, "/admin/settings", "", "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/admin/settings", "", "No se pudo leer el formulario.")
			return
		}
		if r.FormValue("acknowledge") != "1" || strings.TrimSpace(r.FormValue("confirmation")) != "RESET USUARIOS" {
			redirectWithMessage(w, r, "/admin/settings", "", "Confirmación inválida para reset de usuarios.")
			return
		}
		if err := resetUsersData(db); err != nil {
			redirectWithMessage(w, r, "/admin/settings", "", "No se pudo ejecutar el reset de usuarios: "+err.Error())
			return
		}
		if err := writeAuditEvent(db, "admin.reset_users", "system", "", "", userFromContext(r)); err != nil {
			log.Printf("admin/settings/reset-users: audit failed: %v", err)
		}
		clearSessionCookie(w, sessionCookieSecure())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}))

	mux.HandleFunc("/admin/settings/reset-business", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			redirectWithMessage(w, r, "/admin/settings", "", "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/admin/settings", "", "No se pudo leer el formulario.")
			return
		}
		if r.FormValue("acknowledge") != "1" || strings.TrimSpace(r.FormValue("confirmation")) != "RESET INVENTARIO" {
			redirectWithMessage(w, r, "/admin/settings", "", "Confirmación inválida para reset de inventario.")
			return
		}
		if err := resetBusinessData(db); err != nil {
			redirectWithMessage(w, r, "/admin/settings", "", "No se pudo ejecutar el reset de inventario: "+err.Error())
			return
		}
		if err := writeAuditEvent(db, "admin.reset_business", "system", "", "", userFromContext(r)); err != nil {
			log.Printf("admin/settings/reset-business: audit failed: %v", err)
		}
		redirectWithMessage(w, r, "/admin/settings", "Inventario, ventas, cambios, retomas y movimientos fueron eliminados.", "")
	}))

	mux.HandleFunc("/productos/new", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		productsSnapshot, err := loadProductos(db)
		if err != nil {
			http.Error(w, "No se pudo cargar el catálogo", http.StatusInternalServerError)
			return
		}
		nextSKU, err := generateNextProductSKU(db)
		if err != nil {
			http.Error(w, "No se pudo generar el SKU", http.StatusInternalServerError)
			return
		}
		data := productNewData{
			Title:       "Crear producto",
			Subtitle:    "Acción reservada para administradores.",
			Flash:       r.URL.Query().Get("mensaje"),
			SKU:         nextSKU,
			Cantidad:    1,
			Lineas:      buildLineSuggestions(productsSnapshot, ""),
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

		nombre := strings.TrimSpace(r.FormValue("nombre"))
		linea := strings.TrimSpace(r.FormValue("linea"))
		cantidadRaw := strings.TrimSpace(r.FormValue("cantidad"))
		precioVentaRaw := strings.TrimSpace(r.FormValue("precio_venta"))
		aplicaCad := r.FormValue("aplica_caducidad") != ""
		caducidad := strings.TrimSpace(r.FormValue("fecha_caducidad"))

		errors := map[string]string{}
		if nombre == "" {
			errors["nombre"] = "Nombre obligatorio."
		}
		if linea == "" {
			errors["linea"] = "Línea obligatoria."
		}
		precioVenta := 0
		if precioVentaRaw != "" {
			parsedPrice, parseErr := parseCOPInteger(precioVentaRaw)
			if parseErr != nil || parsedPrice < 0 {
				errors["precio_venta"] = "Precio de venta inválido."
			} else {
				precioVenta = parsedPrice
			}
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
			productsSnapshot, snapshotErr := loadProductos(db)
			if snapshotErr != nil {
				http.Error(w, "No se pudo cargar el catálogo", http.StatusInternalServerError)
				return
			}
			nextSKU, skuErr := generateNextProductSKU(db)
			if skuErr != nil {
				http.Error(w, "No se pudo generar el SKU", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			data := productNewData{
				Title:       "Crear producto",
				Subtitle:    "Acción reservada para administradores.",
				SKU:         nextSKU,
				Nombre:      nombre,
				Linea:       linea,
				PrecioVenta: precioVentaRaw,
				Lineas:      buildLineSuggestions(productsSnapshot, linea),
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

		sku, err := generateNextProductSKU(db)
		if err != nil {
			http.Error(w, "No se pudo generar el SKU", http.StatusInternalServerError)
			return
		}
		now := time.Now().Format(time.RFC3339)
		if err := upsertProducto(tx, sku, nombre, linea, now); err != nil {
			http.Error(w, "No se pudo guardar el producto", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec(`UPDATE productos SET precio_venta = ?, precio_venta_cop = ? WHERE sku = ?`, float64(precioVenta), precioVenta, sku); err != nil {
			http.Error(w, "No se pudo guardar el precio del producto", http.StatusInternalServerError)
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
		if err := logAudit(tx, "product.create", "producto", sku, fmt.Sprintf("cantidad=%d", cantidad), userFromContext(r), now); err != nil {
			http.Error(w, "No se pudo registrar auditoría del producto", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			http.Error(w, "No se pudo confirmar la transacción", http.StatusInternalServerError)
			return
		}

		redirectWithMessage(w, r, "/productos/new", "Producto agregado correctamente.", "")
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

		salesData, err := buildDashboardSalesData(db, startStr, endStr, startDate, endDate)
		if err != nil {
			http.Error(w, "Error al consultar ventas", http.StatusInternalServerError)
			return
		}

		data := dashboardData{
			Title:           "Resumen de negocio",
			Subtitle:        "",
			EstadoConteos:   estadoConteos,
			MetodosPago:     salesData.MetodosPago,
			PieSlices:       salesData.PieSlices,
			PieTotal:        salesData.PieTotal,
			MaxTimeline:     salesData.MaxTimeline,
			MaxTimelineText: salesData.MaxTimelineText,
			Timeline:        salesData.Timeline,
			Sales:           salesData.Sales,
			CurrentUser:     currentUser,
			RangeStart:      startStr,
			RangeEnd:        endStr,
			RangeTotal:      salesData.RangeTotal,
			RangeCount:      salesData.RangeCount,
		}

		if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
			http.Error(w, "Error al renderizar el dashboard", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/dashboard/data", func(w http.ResponseWriter, r *http.Request) {
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

		data, err := buildDashboardSalesData(db, startStr, endStr, startDate, endDate)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "No se pudo cargar datos del dashboard."})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	})

	mux.HandleFunc("/dashboard/ventas/delete", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError := func(status int, message string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": message})
		}
		if r.Method != http.MethodPost {
			writeJSONError(http.StatusMethodNotAllowed, "Método no permitido.")
			return
		}
		currentUser := userFromContext(r)
		if currentUser == nil || currentUser.Role != "admin" {
			writeJSONError(http.StatusForbidden, "Solo administrador puede anular ventas.")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSONError(http.StatusBadRequest, "No se pudo leer el formulario.")
			return
		}
		idValue := strings.TrimSpace(r.FormValue("venta_id"))
		ventaID, err := strconv.Atoi(idValue)
		if err != nil || ventaID <= 0 {
			writeJSONError(http.StatusBadRequest, "ID de venta inválido.")
			return
		}
		motivo := strings.TrimSpace(r.FormValue("motivo"))
		tx, err := db.Begin()
		if err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo iniciar la anulación.")
			return
		}
		defer tx.Rollback()
		if err := cancelSale(tx, ventaID, currentUser, motivo); err != nil {
			switch err {
			case errSaleNotFound:
				writeJSONError(http.StatusNotFound, "La venta no existe.")
			case errSaleAlreadyCancelled:
				writeJSONError(http.StatusBadRequest, "La venta ya fue anulada.")
			case errSaleWithoutUnits:
				writeJSONError(http.StatusConflict, "La venta no tiene unidades vinculadas y no puede anularse automáticamente.")
			case errSaleInventoryChanged:
				writeJSONError(http.StatusConflict, "El inventario cambió y la venta no pudo anularse de forma segura.")
			default:
				writeJSONError(http.StatusInternalServerError, "No se pudo completar la anulación.")
			}
			return
		}
		if err := tx.Commit(); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo confirmar la anulación.")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "venta_id": ventaID, "mensaje": "Venta anulada y unidades repuestas."})
	})

	mux.HandleFunc("/csv/ventas", func(w http.ResponseWriter, r *http.Request) {
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

		rows, err := db.Query(`
			SELECT
				v.id,
				v.fecha,
				v.producto_id,
				COALESCE(p.nombre, ''),
				v.cantidad,
				v.precio_unitario_cop,
				v.total_cop,
				v.metodo_pago,
				v.notas
			FROM ventas v
			LEFT JOIN productos p ON p.sku = v.producto_id
			WHERE v.estado = 'confirmada' AND date(v.fecha) BETWEEN ? AND ?
			ORDER BY v.fecha DESC, v.id DESC
		`, startStr, endStr)
		if err != nil {
			http.Error(w, "Error al consultar ventas.", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		filename := fmt.Sprintf("ventas_%s_a_%s.csv", startStr, endStr)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		cw := csv.NewWriter(w)
		defer cw.Flush()

		_ = cw.Write([]string{"venta_id", "fecha", "sku", "producto", "cantidad", "precio_unitario", "total", "metodo_pago", "notas"})

		for rows.Next() {
			var (
				id         int
				fechaRaw   string
				sku        string
				nombre     string
				cantidad   int
				precioUnit int64
				total      int64
				metodo     string
				notas      string
			)
			if err := rows.Scan(&id, &fechaRaw, &sku, &nombre, &cantidad, &precioUnit, &total, &metodo, &notas); err != nil {
				http.Error(w, "Error al leer ventas.", http.StatusInternalServerError)
				return
			}
			fecha := fechaRaw
			if len(fechaRaw) >= 10 {
				fecha = fechaRaw[:10]
			}
			_ = cw.Write([]string{
				strconv.Itoa(id),
				fecha,
				sku,
				nombre,
				strconv.Itoa(cantidad),
				strconv.FormatInt(precioUnit, 10),
				strconv.FormatInt(total, 10),
				metodo,
				notas,
			})
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "Error al procesar ventas.", http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/inventario", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		flash := r.URL.Query().Get("mensaje")
		productsSnapshot, err := loadProductos(db)
		if err != nil {
			http.Error(w, "Error al consultar productos", http.StatusInternalServerError)
			return
		}

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
			counts := countInventoryUnits(units)
			availableCount := counts.available
			reservedCount := counts.reserved
			changeCount := counts.change
			damagedCount := counts.damaged
			internalUseCount := counts.internalUse

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
				} else if internalUseCount > 0 {
					estadoLabel = "Uso interno"
					estadoClass = "internal-use"
				} else {
					estadoLabel = "Vendido"
					estadoClass = "sold"
				}
			}

			// Permanence alert: if the product has been in stock for >= 6 months since fecha_ingreso,
			// flag it for UI and "Accion Caducidad 45 dias" filter.
			fechaIngresoRaw := strings.TrimSpace(product.FechaIngreso)
			if fechaIngresoRaw == "" && len(units) > 0 {
				// Fallback for legacy rows: derive from the oldest unit creation timestamp.
				fechaIngresoRaw = strings.TrimSpace(units[0].CreadoEn)
			}
			mesesEnStock := 0
			fechaIngresoISO := ""
			if t, ok := parseFlexibleTime(fechaIngresoRaw); ok {
				fechaIngresoISO = t.Format("2006-01-02")
				mesesEnStock = monthsBetween(t, time.Now())
			} else if len(fechaIngresoRaw) >= 10 {
				fechaIngresoISO = fechaIngresoRaw[:10]
			}
			alertaPermanencia := mesesEnStock >= 6

			inventoryProducts = append(inventoryProducts, inventoryProduct{
				ID:                product.ID,
				Name:              product.Name,
				Line:              product.Line,
				EstadoLabel:       estadoLabel,
				EstadoClass:       estadoClass,
				Disponible:        availableCount,
				Reservadas:        reservedCount,
				Unidades:          units,
				DisabledSale:      availableCount == 0,
				FechaIngreso:      fechaIngresoISO,
				MesesEnStock:      mesesEnStock,
				AlertaPermanencia: alertaPermanencia,
				SalePrice:         product.SalePrice,
			})
		}
		data := inventoryPageData{
			Title:       "Seguimiento de existencias",
			Subtitle:    "",
			RoutePrefix: "",
			Flash:       flash,
			MetodoPagos: paymentMethods,
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

	mux.HandleFunc("/inventario/uso-interno", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError := func(status int, message string, fields map[string]string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":     false,
				"error":  message,
				"fields": fields,
			})
		}

		if r.Method != http.MethodPost {
			writeJSONError(http.StatusMethodNotAllowed, "Método no permitido.", nil)
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSONError(http.StatusBadRequest, "No se pudo leer el formulario.", nil)
			return
		}

		productID := strings.TrimSpace(r.FormValue("producto_id"))
		uso := strings.TrimSpace(r.FormValue("uso"))
		autorizadoPor := strings.TrimSpace(r.FormValue("autorizado_por"))
		notas := strings.TrimSpace(r.FormValue("notas"))
		qtyValue := strings.TrimSpace(r.FormValue("cantidad"))

		errors := make(map[string]string)
		if productID == "" {
			errors["producto_id"] = "Selecciona un producto válido."
		}
		if uso == "" {
			errors["uso"] = "Ingresa el uso interno."
		}
		if autorizadoPor == "" {
			errors["autorizado_por"] = "Ingresa quién autorizó."
		}
		qty, err := strconv.Atoi(qtyValue)
		if err != nil || qty <= 0 {
			errors["cantidad"] = "La cantidad debe ser un número positivo."
		}
		if len(errors) > 0 {
			message := "Datos inválidos."
			for _, key := range []string{"producto_id", "uso", "autorizado_por", "cantidad"} {
				if msg, ok := errors[key]; ok && msg != "" {
					message = msg
					break
				}
			}
			writeJSONError(http.StatusBadRequest, message, errors)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo iniciar la transacción.", nil)
			return
		}
		defer tx.Rollback()

		unitIDs, err := selectAndMarkUnitsByStatus(tx, productID, qty, "Uso interno")
		if err != nil {
			if err == errInsufficientStock {
				writeJSONError(http.StatusBadRequest, "No hay stock disponible suficiente.", map[string]string{
					"cantidad": "No hay stock disponible suficiente.",
				})
				return
			}
			writeJSONError(http.StatusInternalServerError, "No se pudo registrar el uso interno.", nil)
			return
		}

		parts := []string{
			"Uso: " + uso,
			"Autorizó: " + autorizadoPor,
		}
		if notas != "" {
			parts = append(parts, "Notas: "+notas)
		}
		composedNote := strings.Join(parts, " | ")

		now := time.Now().Format(time.RFC3339)
		if err := logMovimientos(tx, productID, unitIDs, "uso_interno", composedNote, userFromContext(r), now); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo registrar el movimiento.", nil)
			return
		}

		if err := tx.Commit(); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo confirmar la transacción.", nil)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"producto_id": productID,
			"cantidad":    qty,
			"mensaje":     "Uso interno registrado correctamente.",
		})
	})

	mux.HandleFunc("/inventario/stock", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError := func(status int, message string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
		}

		currentUser := userFromContext(r)

		if r.Method != http.MethodPost {
			writeJSONError(http.StatusMethodNotAllowed, "Método no permitido.")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSONError(http.StatusBadRequest, "No se pudo leer el formulario.")
			return
		}
		productID := strings.TrimSpace(r.FormValue("producto_id"))
		targetValue := strings.TrimSpace(r.FormValue("cantidad"))
		nota := strings.TrimSpace(r.FormValue("nota"))
		priceValue := strings.TrimSpace(r.FormValue("precio_venta"))
		nameValue := strings.TrimSpace(r.FormValue("nombre"))
		lineValue := strings.TrimSpace(r.FormValue("linea"))
		target, err := strconv.Atoi(targetValue)
		if productID == "" || err != nil || target < 0 {
			writeJSONError(http.StatusBadRequest, "Cantidad objetivo inválida.")
			return
		}
		if nameValue == "" {
			writeJSONError(http.StatusBadRequest, "El nombre del producto es obligatorio.")
			return
		}
		if lineValue == "" {
			writeJSONError(http.StatusBadRequest, "La línea del producto es obligatoria.")
			return
		}
		newPrice := int64(0)
		if priceValue != "" {
			parsed, err := parseCOPInteger(priceValue)
			if err != nil || parsed < 0 {
				writeJSONError(http.StatusBadRequest, "Precio de venta inválido.")
				return
			}
			newPrice = int64(parsed)
		}

		tx, err := db.Begin()
		if err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo iniciar la transacción.")
			return
		}
		defer tx.Rollback()
		var existingProduct string
		if err := tx.QueryRow(`SELECT sku FROM productos WHERE sku = ?`, productID).Scan(&existingProduct); err != nil {
			if err == sql.ErrNoRows {
				writeJSONError(http.StatusBadRequest, "Producto inválido.")
			} else {
				writeJSONError(http.StatusInternalServerError, "No se pudo validar el producto.")
			}
			return
		}

		rows, err := tx.Query(`
			SELECT id
			FROM unidades
			WHERE producto_id = ? AND estado IN ('Disponible', 'available')
			ORDER BY creado_en DESC, id DESC
		`, productID)
		if err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo consultar el stock actual.")
			return
		}
		availableIDs := make([]string, 0, 64)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				writeJSONError(http.StatusInternalServerError, "No se pudo leer el stock actual.")
				return
			}
			availableIDs = append(availableIDs, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			writeJSONError(http.StatusInternalServerError, "No se pudo procesar el stock actual.")
			return
		}
		rows.Close()

		current := len(availableIDs)
		delta := target - current
		now := time.Now().Format(time.RFC3339)
		if delta > 0 {
			createdIDs := make([]string, 0, delta)
			baseID := time.Now().UnixNano()
			for i := 0; i < delta; i++ {
				unitID := fmt.Sprintf("U-%s-AJ-%d-%d", productID, baseID, i)
				if _, err := tx.Exec(
					`INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad) VALUES (?, ?, ?, ?, ?)`,
					unitID, productID, "Disponible", now, nil,
				); err != nil {
					writeJSONError(http.StatusInternalServerError, "No se pudo incrementar el stock.")
					return
				}
				createdIDs = append(createdIDs, unitID)
			}
			logNote := nota
			if logNote == "" {
				logNote = fmt.Sprintf("Ajuste manual de stock: %d -> %d", current, target)
			}
			if err := logMovimientos(tx, productID, createdIDs, "ajuste_stock_entrada", logNote, currentUser, now); err != nil {
				writeJSONError(http.StatusInternalServerError, "No se pudo registrar el ajuste.")
				return
			}
		} else if delta < 0 {
			removeCount := -delta
			if removeCount > len(availableIDs) {
				writeJSONError(http.StatusBadRequest, "No hay stock suficiente para reducir a ese valor.")
				return
			}
			removeIDs := availableIDs[:removeCount]
			placeholders := make([]string, len(removeIDs))
			args := make([]any, 0, len(removeIDs)+1)
			for i, id := range removeIDs {
				placeholders[i] = "?"
				args = append(args, id)
			}
			args = append(args, productID)
			query := fmt.Sprintf(
				"DELETE FROM unidades WHERE id IN (%s) AND producto_id = ? AND estado IN ('Disponible', 'available')",
				strings.Join(placeholders, ","),
			)
			res, err := tx.Exec(query, args...)
			if err != nil {
				writeJSONError(http.StatusInternalServerError, "No se pudo reducir el stock.")
				return
			}
			affected, err := res.RowsAffected()
			if err != nil || int(affected) != removeCount {
				writeJSONError(http.StatusInternalServerError, "No se pudo confirmar el ajuste de stock.")
				return
			}
			logNote := nota
			if logNote == "" {
				logNote = fmt.Sprintf("Ajuste manual de stock: %d -> %d", current, target)
			}
			if err := logMovimientos(tx, productID, removeIDs, "ajuste_stock_salida", logNote, currentUser, now); err != nil {
				writeJSONError(http.StatusInternalServerError, "No se pudo registrar el ajuste.")
				return
			}
		}
		if _, err := tx.Exec(
			`UPDATE productos SET nombre = ?, linea = ?, precio_venta = ?, precio_venta_cop = ? WHERE sku = ?`,
			nameValue, lineValue, float64(newPrice), newPrice, productID,
		); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo actualizar el producto.")
			return
		}
		if err := logAudit(tx, "product.stock_update", "producto", productID, fmt.Sprintf("stock=%d precio_venta_cop=%d", target, newPrice), currentUser, now); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo registrar auditoría del ajuste.")
			return
		}

		if err := tx.Commit(); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo confirmar la transacción.")
			return
		}
		message := "Producto actualizado correctamente."
		if delta != 0 {
			message = "Producto y stock actualizados correctamente."
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"producto_id": productID,
			"actual":      target,
			"objetivo":    target,
			"delta":       delta,
			"mensaje":     message,
		})
	}))

	mux.HandleFunc("/inventario/producto/eliminar", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError := func(status int, message string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
		}

		currentUser := userFromContext(r)
		if currentUser == nil || currentUser.Role != "admin" {
			writeJSONError(http.StatusForbidden, "Solo administrador puede eliminar productos.")
			return
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
		if productID == "" {
			writeJSONError(http.StatusBadRequest, "Producto inválido.")
			return
		}

		tx, err := db.Begin()
		if err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo iniciar la transacción.")
			return
		}
		defer tx.Rollback()

		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = ? OR id = ?`, productID, productID).Scan(&exists); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo validar el producto.")
			return
		}
		if exists == 0 {
			writeJSONError(http.StatusBadRequest, "Producto inválido.")
			return
		}

		if _, err := tx.Exec(`DELETE FROM unidades WHERE producto_id = ?`, productID); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudieron eliminar las unidades del producto.")
			return
		}

		// Legacy compatibility: if the table exists, clear price history rows before deleting the product.
		var hasPriceHistoryTable int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'precio_venta_historial'`).Scan(&hasPriceHistoryTable); err == nil && hasPriceHistoryTable > 0 {
			histCols := map[string]bool{}
			colRows, err := tx.Query(`PRAGMA table_info('precio_venta_historial')`)
			if err == nil {
				for colRows.Next() {
					var cid int
					var name, colType string
					var notNull, pk int
					var dflt sql.NullString
					if scanErr := colRows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); scanErr == nil {
						histCols[strings.ToLower(strings.TrimSpace(name))] = true
					}
				}
				colRows.Close()
			}

			switch {
			case histCols["producto_id"]:
				if _, err := tx.Exec(`DELETE FROM precio_venta_historial WHERE producto_id = ?`, productID); err != nil {
					writeJSONError(http.StatusInternalServerError, "No se pudo limpiar el historial de precio del producto.")
					return
				}
			case histCols["product_id"]:
				if _, err := tx.Exec(`DELETE FROM precio_venta_historial WHERE product_id = ?`, productID); err != nil {
					writeJSONError(http.StatusInternalServerError, "No se pudo limpiar el historial de precio del producto.")
					return
				}
			case histCols["producto_sku"]:
				if _, err := tx.Exec(`DELETE FROM precio_venta_historial WHERE producto_sku = ?`, productID); err != nil {
					writeJSONError(http.StatusInternalServerError, "No se pudo limpiar el historial de precio del producto.")
					return
				}
			case histCols["sku"]:
				if _, err := tx.Exec(`DELETE FROM precio_venta_historial WHERE sku = ?`, productID); err != nil {
					writeJSONError(http.StatusInternalServerError, "No se pudo limpiar el historial de precio del producto.")
					return
				}
			}
		}

		res, err := tx.Exec(`DELETE FROM productos WHERE sku = ? OR id = ?`, productID, productID)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "foreign key") {
				writeJSONError(http.StatusBadRequest, "No se pudo eliminar el producto porque tiene referencias activas.")
				return
			}
			writeJSONError(http.StatusInternalServerError, "No se pudo eliminar el producto.")
			return
		}
		affected, err := res.RowsAffected()
		if err != nil || affected == 0 {
			writeJSONError(http.StatusBadRequest, "No se pudo confirmar la eliminación del producto.")
			return
		}
		if err := logAudit(tx, "product.delete", "producto", productID, "", currentUser, time.Now().Format(time.RFC3339)); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo registrar auditoría de la eliminación.")
			return
		}

		if err := tx.Commit(); err != nil {
			writeJSONError(http.StatusInternalServerError, "No se pudo confirmar la transacción.")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"producto_id": productID,
			"mensaje":     "Producto eliminado correctamente.",
		})
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

	mux.HandleFunc("/api/productos/precio", func(w http.ResponseWriter, r *http.Request) {
		sku := strings.TrimSpace(r.URL.Query().Get("sku"))
		if sku == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Falta sku."})
			return
		}

		var precioVenta int64
		err := db.QueryRow(`SELECT COALESCE(precio_venta_cop, 0) FROM productos WHERE sku = ?`, sku).Scan(&precioVenta)
		if err != nil {
			if err == sql.ErrNoRows {
				precioVenta = 0
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "No se pudo consultar el precio."})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "sku": sku, "precio_venta": precioVenta})
	})

	mux.HandleFunc("/venta/new", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)

		productsSnapshot, err := loadProductos(db)
		if err != nil {
			http.Error(w, "Error al consultar productos", http.StatusInternalServerError)
			return
		}
		if len(productsSnapshot) == 0 {
			http.Error(w, "No hay productos en el catálogo.", http.StatusConflict)
			return
		}

		productID := r.URL.Query().Get("producto_id")
		if productID == "" && len(productsSnapshot) > 0 {
			productID = productsSnapshot[0].ID
		}
		cantidad := 1
		if qty := r.URL.Query().Get("cantidad"); qty != "" {
			if parsed, err := strconv.Atoi(qty); err == nil && parsed > 0 {
				cantidad = parsed
			}
		}

		selectedProduct, ok := findProduct(productsSnapshot, productID)
		if !ok && len(productsSnapshot) > 0 {
			selectedProduct = productsSnapshot[0]
			productID = selectedProduct.ID
		}

		stockByProd, err := availableCountsByProduct(db)
		if err != nil {
			http.Error(w, "Error al consultar stock", http.StatusInternalServerError)
			return
		}
		if available := stockByProd[productID]; available > 0 && cantidad > available {
			cantidad = available
		}

		data := ventaFormData{
			Title:       "Registrar venta",
			ProductoID:  productID,
			ProductoNom: selectedProduct.Name,
			Productos:   productsSnapshot,
			StockByProd: stockByProd,
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
		productsSnapshot, err := loadProductos(db)
		if err != nil {
			http.Error(w, "Error al consultar productos", http.StatusInternalServerError)
			return
		}
		if len(productsSnapshot) == 0 {
			http.Error(w, "No hay productos en el catálogo.", http.StatusConflict)
			return
		}

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
		wantsJSON := strings.Contains(r.Header.Get("Accept"), "application/json") || r.Header.Get("X-Requested-With") == "XMLHttpRequest"

		writeJSONError := func(status int, message string, fields map[string]string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":     false,
				"error":  message,
				"fields": fields,
			})
		}

		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/venta/new", http.StatusSeeOther)
			return
		}

		productsSnapshot, err := loadProductos(db)
		if err != nil {
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al consultar productos.", nil)
				return
			}
			http.Error(w, "Error al consultar productos", http.StatusInternalServerError)
			return
		}
		if len(productsSnapshot) == 0 {
			if wantsJSON {
				writeJSONError(http.StatusConflict, "No hay productos en el catálogo.", nil)
				return
			}
			http.Error(w, "No hay productos en el catálogo.", http.StatusConflict)
			return
		}

		stockByProd, err := availableCountsByProduct(db)
		if err != nil {
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al consultar stock.", nil)
				return
			}
			http.Error(w, "Error al consultar stock", http.StatusInternalServerError)
			return
		}

		if err := r.ParseForm(); err != nil {
			if wantsJSON {
				writeJSONError(http.StatusBadRequest, "No se pudo leer el formulario.", nil)
				return
			}
			http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
			return
		}

		productID := r.FormValue("producto_id")
		qtyValue := r.FormValue("cantidad")
		precioValue := r.FormValue("precio_final_venta")
		valorVentaFinalValue := r.FormValue("valor_venta_final")
		metodoPago := r.FormValue("metodo_pago")
		notas := r.FormValue("notas")

		selectedProduct, ok := findProduct(productsSnapshot, productID)
		if !ok && len(productsSnapshot) > 0 {
			selectedProduct = productsSnapshot[0]
		}

		errors := make(map[string]string)
		cantidad, err := strconv.Atoi(qtyValue)
		if err != nil || cantidad <= 0 {
			errors["cantidad"] = "La cantidad debe ser un número positivo."
		}
		if productID == "" {
			errors["producto_id"] = "Selecciona un producto válido."
		} else if !ok {
			errors["producto_id"] = "Selecciona un producto válido."
		}
		precioParsed := int64(0)
		precioOk := false
		if strings.TrimSpace(precioValue) != "" {
			if parsed, err := parseCOPInteger(precioValue); err == nil && parsed > 0 {
				precioParsed = int64(parsed)
				precioOk = true
			} else {
				errors["precio_final_venta"] = "El precio debe ser un número mayor a 0."
			}
		}

		valorFinalParsed := int64(0)
		valorFinalOk := false
		if strings.TrimSpace(valorVentaFinalValue) != "" {
			if parsed, err := parseCOPInteger(valorVentaFinalValue); err == nil && parsed > 0 {
				valorFinalParsed = int64(parsed)
				valorFinalOk = true
			} else {
				errors["valor_venta_final"] = "El valor final debe ser un número mayor a 0."
			}
		}

		if !valorFinalOk && !precioOk {
			if _, ok := errors["precio_final_venta"]; !ok {
				errors["precio_final_venta"] = "Ingresa el precio unitario o el valor final de la venta."
			}
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

		if productID != "" && cantidad > 0 {
			if available := stockByProd[productID]; available > 0 && cantidad > available {
				errors["cantidad"] = "No hay stock disponible suficiente para completar la venta."
			}
		}

		if len(errors) > 0 {
			if wantsJSON {
				message := "Datos inválidos."
				// Pick the first field error as a message for the modal.
				for _, key := range []string{"producto_id", "cantidad", "valor_venta_final", "precio_final_venta", "metodo_pago"} {
					if msg, ok := errors[key]; ok && msg != "" {
						message = msg
						break
					}
				}
				writeJSONError(http.StatusBadRequest, message, errors)
				return
			}
			data := ventaFormData{
				Title:           "Registrar venta",
				ProductoID:      productID,
				ProductoNom:     selectedProduct.Name,
				Productos:       productsSnapshot,
				StockByProd:     stockByProd,
				Cantidad:        cantidad,
				PrecioFinal:     precioValue,
				ValorVentaFinal: valorVentaFinalValue,
				MetodoPago:      metodoPago,
				Notas:           notas,
				Errors:          errors,
				MetodoPagos:     paymentMethods,
				CurrentUser:     currentUser,
			}
			w.WriteHeader(http.StatusBadRequest)
			if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
				http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
			}
			return
		}

		precioFinal := precioParsed
		totalVenta := precioFinal * int64(cantidad)
		precioFinalText := precioValue
		if valorFinalOk && cantidad > 0 {
			totalVenta = valorFinalParsed
			precioFinal = totalVenta / int64(cantidad)
			precioFinalText = strconv.FormatInt(precioFinal, 10)
		}
		tx, err := db.Begin()
		if err != nil {
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al procesar la venta.", nil)
				return
			}
			http.Error(w, "Error al procesar la venta", http.StatusInternalServerError)
			return
		}

		soldUnitIDs, err := selectAndMarkUnitsSold(tx, productID, cantidad)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback venta: %v", rollbackErr)
			}
			if err == errInsufficientStock {
				if wantsJSON {
					writeJSONError(http.StatusBadRequest, "No hay stock disponible suficiente para completar la venta.", map[string]string{
						"cantidad": "No hay stock disponible suficiente para completar la venta.",
					})
					return
				}
				errors["cantidad"] = "No hay stock disponible suficiente para completar la venta."
				data := ventaFormData{
					Title:           "Registrar venta",
					ProductoID:      productID,
					Cantidad:        cantidad,
					PrecioFinal:     precioValue,
					ValorVentaFinal: valorVentaFinalValue,
					MetodoPago:      metodoPago,
					Notas:           notas,
					Errors:          errors,
					MetodoPagos:     paymentMethods,
				}
				w.WriteHeader(http.StatusBadRequest)
				if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
					http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
				}
				return
			}
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al actualizar inventario.", nil)
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
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al registrar movimiento de venta.", nil)
				return
			}
			http.Error(w, "Error al registrar movimiento de venta", http.StatusInternalServerError)
			return
		}

		result, err := tx.Exec(
			`INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			productID, cantidad, float64(precioFinal), metodoPago, notas, now, precioFinal, totalVenta,
		)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback venta insert: %v", rollbackErr)
			}
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al registrar la venta.", nil)
				return
			}
			http.Error(w, "Error al registrar la venta", http.StatusInternalServerError)
			return
		}
		saleID, err := result.LastInsertId()
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback venta id: %v", rollbackErr)
			}
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al vincular la venta.", nil)
				return
			}
			http.Error(w, "Error al vincular la venta", http.StatusInternalServerError)
			return
		}
		for _, unitID := range soldUnitIDs {
			if _, err := tx.Exec(`INSERT INTO venta_unidades (venta_id, unidad_id) VALUES (?, ?)`, saleID, unitID); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					log.Printf("rollback venta unidades: %v", rollbackErr)
				}
				if wantsJSON {
					writeJSONError(http.StatusInternalServerError, "Error al vincular unidades de la venta.", nil)
					return
				}
				http.Error(w, "Error al vincular unidades de la venta", http.StatusInternalServerError)
				return
			}
		}

		if err := tx.Commit(); err != nil {
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al confirmar la venta.", nil)
				return
			}
			http.Error(w, "Error al confirmar la venta", http.StatusInternalServerError)
			return
		}

		if wantsJSON {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"producto_id":  productID,
				"producto_nom": selectedProduct.Name,
				"cantidad":     cantidad,
				"mensaje":      "Venta registrada correctamente.",
			})
			return
		}

		confirmData := ventaConfirmData{
			Title:           "Venta registrada",
			ProductoID:      productID,
			ProductoNom:     selectedProduct.Name,
			Cantidad:        cantidad,
			PrecioFinal:     precioFinalText,
			ValorVentaFinal: valorVentaFinalValue,
			MetodoPago:      metodoPago,
			Notas:           notas,
			CurrentUser:     currentUser,
		}
		if err := tmpl.ExecuteTemplate(w, "venta_confirm.html", confirmData); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/cambio", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		wantsJSON := strings.Contains(r.Header.Get("Accept"), "application/json") || r.Header.Get("X-Requested-With") == "XMLHttpRequest"

		writeJSONError := func(status int, message string, fields map[string]string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":     false,
				"error":  message,
				"fields": fields,
			})
		}

		productsSnapshot, err := loadProductos(db)
		if err != nil {
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al consultar productos.", nil)
				return
			}
			http.Error(w, "Error al consultar productos", http.StatusInternalServerError)
			return
		}
		if len(productsSnapshot) == 0 {
			if wantsJSON {
				writeJSONError(http.StatusConflict, "No hay productos en el catálogo.", nil)
				return
			}
			http.Error(w, "No hay productos en el catálogo.", http.StatusConflict)
			return
		}

		if r.Method != http.MethodPost {
			if wantsJSON {
				writeJSONError(http.StatusMethodNotAllowed, "Método no permitido.", nil)
				return
			}
			http.Redirect(w, r, "/cambio/new", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			if wantsJSON {
				writeJSONError(http.StatusBadRequest, "No se pudo leer el formulario.", nil)
				return
			}
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
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al consultar unidades disponibles.", nil)
				return
			}
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
			} else if _, exists := findProduct(productsSnapshot, incomingExistingID); !exists {
				errors["incoming_existing_id"] = "El producto entrante no es válido."
			}
			if incomingExistingQty <= 0 {
				errors["incoming_existing_qty"] = "Ingresa una cantidad válida para la entrada."
			}
		} else if incomingMode == "new" {
			if incomingNewSKU == "" {
				errors["incoming_new_sku"] = "Ingresa el SKU del producto nuevo."
			} else if _, exists := findProduct(productsSnapshot, incomingNewSKU); exists {
				errors["incoming_new_sku"] = "El SKU ya existe; selecciona el producto existente."
			}
			if incomingNewName == "" {
				errors["incoming_new_name"] = "Ingresa el nombre del producto nuevo."
			}
			if incomingNewQty <= 0 {
				errors["incoming_new_qty"] = "Ingresa una cantidad válida para la entrada."
			}
		}

		if len(errors) > 0 {
			if wantsJSON {
				message := "Datos inválidos."
				for _, key := range []string{"producto_id", "persona_del_cambio", "salientes", "incoming_mode", "incoming_existing_id", "incoming_existing_qty", "incoming_new_sku", "incoming_new_name", "incoming_new_qty"} {
					if msg, ok := errors[key]; ok && msg != "" {
						message = msg
						break
					}
				}
				writeJSONError(http.StatusBadRequest, message, errors)
				return
			}
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
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al iniciar el cambio.", nil)
				return
			}
			http.Error(w, "Error al iniciar el cambio", http.StatusInternalServerError)
			return
		}

		salientesMarcadas, err := selectAndMarkSpecificUnits(tx, productID, salientes, "Cambio")
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback cambio: %v", rollbackErr)
			}
			if err == errInsufficientStock {
				if wantsJSON {
					writeJSONError(http.StatusBadRequest, "No hay stock disponible suficiente para completar el cambio.", map[string]string{
						"salientes": "No hay stock disponible suficiente para completar el cambio.",
					})
					return
				}
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
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al actualizar unidades salientes.", nil)
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
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al registrar movimiento del cambio.", nil)
				return
			}
			http.Error(w, "Error al registrar movimiento del cambio", http.StatusInternalServerError)
			return
		}

		entrantes := make([]string, 0)

		incomingProductID := incomingExistingID
		incomingQty := incomingExistingQty
		if incomingMode == "new" {
			incomingProductID = incomingNewSKU
			incomingQty = incomingNewQty
			incomingLine := strings.TrimSpace(incomingNewLine)
			if incomingLine == "" {
				incomingLine = "Sin línea"
			}
			if err := upsertProducto(tx, incomingProductID, incomingNewName, incomingLine, now); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					log.Printf("rollback cambio producto entrante: %v", rollbackErr)
				}
				if wantsJSON {
					writeJSONError(http.StatusInternalServerError, "Error al registrar el producto entrante.", nil)
					return
				}
				http.Error(w, "Error al registrar el producto entrante", http.StatusInternalServerError)
				return
			}
		}

		baseIncomingID := time.Now().UnixNano()
		for i := 0; i < incomingQty; i++ {
			unitID := fmt.Sprintf("U-%s-%d-%d", incomingProductID, baseIncomingID, i+1)
			if _, err := tx.Exec(
				`INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad)
				VALUES (?, ?, ?, ?, ?)`,
				unitID, incomingProductID, "Disponible", now, nil,
			); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					log.Printf("rollback cambio insert: %v", rollbackErr)
				}
				if wantsJSON {
					writeJSONError(http.StatusInternalServerError, "Error al registrar unidades entrantes.", nil)
					return
				}
				http.Error(w, "Error al registrar unidades entrantes", http.StatusInternalServerError)
				return
			}
			entrantes = append(entrantes, unitID)
		}
		if err := logMovimientos(tx, incomingProductID, entrantes, "cambio_entrada", notaMovimiento, currentUser, now); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback cambio entrada log: %v", rollbackErr)
			}
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al registrar movimiento de entrada.", nil)
				return
			}
			http.Error(w, "Error al registrar movimiento de entrada", http.StatusInternalServerError)
			return
		}
		if err := logAudit(tx, "inventory.change", "producto", productID, fmt.Sprintf("salientes=%d entrantes=%d", len(salientesMarcadas), len(entrantes)), currentUser, now); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Printf("rollback cambio audit: %v", rollbackErr)
			}
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al registrar auditoría del cambio.", nil)
				return
			}
			http.Error(w, "Error al registrar auditoría del cambio", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al confirmar el cambio.", nil)
				return
			}
			http.Error(w, "Error al confirmar el cambio", http.StatusInternalServerError)
			return
		}
		if wantsJSON {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":              true,
				"producto_id":     productID,
				"producto_nombre": selectedProduct.Name,
				"salientes":       salientesMarcadas,
				"entrantes":       entrantes,
				"mensaje":         "Cambio registrado correctamente.",
			})
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

		const maxCSVUploadBytes = 32 << 20
		r.Body = http.MaxBytesReader(w, r.Body, maxCSVUploadBytes)
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
		if len(records) > 10001 {
			writeJSONError(http.StatusRequestEntityTooLarge, "El CSV supera el máximo de 10.000 filas.")
			return
		}
		for _, row := range records {
			if len(row) > 32 {
				writeJSONError(http.StatusBadRequest, "El CSV contiene demasiadas columnas.")
				return
			}
			for _, cell := range row {
				if len(cell) > 4096 {
					writeJSONError(http.StatusBadRequest, "El CSV contiene una celda demasiado larga.")
					return
				}
			}
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

		parseCSVMoney := func(value string) (int64, error) {
			parsed, err := parseCOPInteger(value)
			return int64(parsed), err
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
			if cantidadRaw == "-" {
				cantidadRaw = "0"
			}

			if sku == "" || linea == "" || nombre == "" {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "SKU, línea y nombre son obligatorios."})
				continue
			}

			cantidad, err := parseCSVInt(cantidadRaw)
			if err != nil || cantidad < 0 {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Cantidad inválida (debe ser 0 o mayor)."})
				continue
			}

			// Validate numeric columns.
			precioBase, err := parseCSVMoney(get(row, "precio_base"))
			if err != nil {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Precio base inválido."})
				continue
			}
			precioVenta, err := parseCSVMoney(get(row, "precio_venta"))
			if err != nil {
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Precio venta inválido."})
				continue
			}
			precioConsultora, err := parseCSVMoney(get(row, "precio_consultora"))
			if err != nil {
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
			var existingProductCount int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = ?`, sku).Scan(&existingProductCount); err != nil {
				_, _ = tx.Exec("ROLLBACK TO csv_row")
				_, _ = tx.Exec("RELEASE csv_row")
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Error al comprobar producto."})
				continue
			}

			// Persist catalog.
			if err := upsertProducto(tx, sku, nombre, linea, now); err != nil {
				_, _ = tx.Exec("ROLLBACK TO csv_row")
				_, _ = tx.Exec("RELEASE csv_row")
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Error al guardar producto."})
				continue
			}
			if _, err := tx.Exec(`
				UPDATE productos
				SET precio_base = ?, precio_venta = ?, precio_consultora = ?,
				    precio_base_cop = ?, precio_venta_cop = ?, precio_consultora_cop = ?
				WHERE sku = ?`,
				float64(precioBase), float64(precioVenta), float64(precioConsultora),
				precioBase, precioVenta, precioConsultora, sku); err != nil {
				_, _ = tx.Exec("ROLLBACK TO csv_row")
				_, _ = tx.Exec("RELEASE csv_row")
				resp.FailedRows = append(resp.FailedRows, csvFailedRow{Row: rowIndex, SKU: sku, Error: "Error al guardar precio de venta."})
				continue
			}

			// Insert units into DB (inventory source of truth).
			baseID := time.Now().UnixNano()
			rowFailed := false
			rowCreatedUnits := 0
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
				rowCreatedUnits++
			}

			if rowFailed {
				continue
			}
			_, _ = tx.Exec("RELEASE csv_row")
			if existingProductCount == 1 {
				resp.UpdatedProducts++
			} else {
				resp.CreatedProducts++
			}
			resp.CreatedUnits += rowCreatedUnits
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
	server := &http.Server{
		Addr:              addr,
		Handler:           requestLoggingMiddleware(securityHeadersMiddleware(requestLimitsMiddleware(authMiddleware(db, csrfMiddleware(mux))))),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error al cerrar servidor: %v", err)
		}
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
