package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
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

const (
	checkoutChargeProductID = "__CARGO_DIFERENCIA__"
	checkoutStateDraft      = "borrador"
	checkoutStatePartial    = "parcial"
	checkoutStateConfirmed  = "confirmado"
	checkoutStateDiscarded  = "descartado"
	checkoutLinePending     = "pendiente"
	checkoutLineProcessed   = "procesada"
	checkoutLineError       = "error"
	checkoutLineDiscarded   = "descartada"
)

type checkoutOperation struct {
	ID           int64
	UserID       int
	Cliente      string
	MetodoPago   string
	Notas        string
	Estado       string
	TotalCOP     int64
	TotalText    string
	CreatedAt    string
	UpdatedAt    string
	ItemCount    int
	PendingCount int
}

type checkoutSaleItem struct {
	ID                int64
	CheckoutID        int64
	Tipo              string
	ProductoID        string
	ProductoNombre    string
	Cantidad          int
	PrecioUnitarioCOP int64
	TotalCOP          int64
	PrecioText        string
	TotalText         string
	Notas             string
	Orden             int
	Estado            string
	Error             string
	VentaID           sql.NullInt64
	CreatedAt         string
	UpdatedAt         string
}

type checkoutChangeItem struct {
	ID             int64
	CheckoutID     int64
	Direccion      string
	ProductoID     string
	ProductoNombre string
	Linea          string
	Cantidad       int
	EsNuevo        bool
	Orden          int
	Estado         string
	Error          string
	ProcessedAt    string
	CreatedAt      string
	UpdatedAt      string
}

type checkoutItemRef struct {
	Kind  string
	ID    int64
	Order int
}

type checkoutProcessResult struct {
	CheckoutID        int64
	State             string
	ProcessedCount    int
	FailedCount       int
	PendingCount      int
	ProcessedTotalCOP int64
	Errors            []string
}

type checkoutSaleInput struct {
	Tipo              string
	ProductoID        string
	ProductoNombre    string
	Cantidad          int
	PrecioUnitarioCOP int64
	TotalCOP          int64
	Notas             string
}

type checkoutChangeInput struct {
	Direccion      string
	ProductoID     string
	ProductoNombre string
	Linea          string
	Cantidad       int
	EsNuevo        bool
}

type checkoutPageData struct {
	Title          string
	Subtitle       string
	Flash          string
	Error          string
	Checkout       checkoutOperation
	SaleItems      []checkoutSaleItem
	ChangeItems    []checkoutChangeItem
	Products       []productOption
	StockByProduct map[string]int
	PaymentMethods []string
	CurrentUser    *User
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

const (
	maxCambioQuantity    = 10000
	maxCambioSKUBytes    = 80
	maxCambioNameBytes   = 180
	maxCambioLineBytes   = 120
	maxCambioPersonBytes = 160
	maxCambioNotesBytes  = 2000
)

var (
	errInsufficientStock       = fmt.Errorf("stock insuficiente")
	errCambioIncomingSKUExists = fmt.Errorf("el SKU del producto entrante ya existe")
)

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
	Multi               bool
	OutLines            []cambioLineDraft
	InLines             []cambioLineDraft
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
	SalienteLines       []cambioConfirmLine
	EntranteLines       []cambioConfirmLine
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
	Cambios  int    `json:"cambios"`
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

type dashboardChange struct {
	ID               int64  `json:"id"`
	Fecha            string `json:"fecha"`
	Persona          string `json:"persona"`
	SalienteSKU      string `json:"saliente_sku"`
	SalienteProducto string `json:"saliente_producto"`
	SalienteCantidad int    `json:"saliente_cantidad"`
	EntranteSKU      string `json:"entrante_sku"`
	EntranteProducto string `json:"entrante_producto"`
	EntranteCantidad int    `json:"entrante_cantidad"`
	Motivo           string `json:"motivo"`
	Usuario          string `json:"usuario"`
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
	ChangeCount     int
	Changes         []dashboardChange
}

type dashboardDataResponse struct {
	Ok bool `json:"ok"`

	RangeStart  string `json:"range_start"`
	RangeEnd    string `json:"range_end"`
	RangeTotal  string `json:"range_total"`
	RangeCount  int    `json:"range_count"`
	ChangeCount int    `json:"change_count"`

	MetodosPago     []metodoPagoTotal     `json:"metodos_pago"`
	PieSlices       []pieSlice            `json:"pie_slices"`
	PieTotal        string                `json:"pie_total"`
	MaxTimeline     int64                 `json:"max_timeline"`
	MaxTimelineText string                `json:"max_timeline_text"`
	Timeline        []timelinePoint       `json:"timeline"`
	Sales           []dashboardSaleDetail `json:"sales"`
	Changes         []dashboardChange     `json:"changes"`
}

func buildDashboardData(db *sql.DB, startStr, endStr string, startDate, endDate time.Time) (dashboardDataResponse, error) {
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

	var changeCount int
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM (
			SELECT id
			FROM cambio_operaciones
			WHERE date(fecha) BETWEEN ? AND ?
			UNION ALL
			SELECT c.id
			FROM checkout_operaciones c
			WHERE c.estado IN ('parcial', 'confirmado')
			  AND date(c.updated_at) BETWEEN ? AND ?
			  AND EXISTS (
				SELECT 1
				FROM checkout_cambio_items i
				WHERE i.checkout_id = c.id AND i.estado = 'procesada'
			  )
		)`, startStr, endStr, startStr, endStr).Scan(&changeCount); err != nil {
		return dashboardDataResponse{}, err
	}
	resp.ChangeCount = changeCount

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

	changeRows, err := db.Query(`
		SELECT fecha, COUNT(*)
		FROM (
			SELECT date(fecha) AS fecha
			FROM cambio_operaciones
			WHERE date(fecha) BETWEEN ? AND ?
			UNION ALL
			SELECT date(c.updated_at) AS fecha
			FROM checkout_operaciones c
			WHERE c.estado IN ('parcial', 'confirmado')
			  AND date(c.updated_at) BETWEEN ? AND ?
			  AND EXISTS (
				SELECT 1
				FROM checkout_cambio_items i
				WHERE i.checkout_id = c.id AND i.estado = 'procesada'
			  )
		)
		GROUP BY fecha
		ORDER BY fecha`, startStr, endStr, startStr, endStr)
	if err != nil {
		return dashboardDataResponse{}, err
	}
	defer changeRows.Close()

	changesByDate := make(map[string]int)
	for changeRows.Next() {
		var fecha string
		var count int
		if err := changeRows.Scan(&fecha, &count); err != nil {
			return dashboardDataResponse{}, err
		}
		changesByDate[fecha] = count
	}
	if err := changeRows.Err(); err != nil {
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
				Cambios:  changesByDate[fecha],
				Total:    formatCurrency(0),
				Value:    0,
			}
		} else {
			point.Cambios = changesByDate[fecha]
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
			COALESCE(NULLIF(v.producto_nombre, ''), p.nombre, v.producto_id),
			v.cantidad,
			v.total_cop,
			v.metodo_pago,
			COALESCE(v.tipo, 'producto')
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
			tipo       string
		)
		if err := saleRows.Scan(&id, &fechaRaw, &producto, &cantidad, &total, &metodoPago, &tipo); err != nil {
			return dashboardDataResponse{}, err
		}
		fecha := fechaRaw
		if len(fechaRaw) >= 10 {
			fecha = fechaRaw[:10]
		}
		tipoLabel := "Venta"
		if tipo == "cargo" {
			tipoLabel = "Cargo"
		}
		sales = append(sales, dashboardSaleDetail{
			ID:         id,
			Fecha:      fecha,
			Producto:   producto,
			Cantidad:   cantidad,
			Total:      formatCurrency(total),
			MetodoPago: metodoPago,
			Tipo:       tipoLabel,
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

	detailRows, err := db.Query(`
		SELECT id, fecha, persona, saliente_sku, saliente_producto,
		       saliente_cantidad, entrante_sku, entrante_producto,
		       entrante_cantidad, motivo, usuario
		FROM (
			SELECT
				o.id,
				o.fecha,
				o.persona_cambio AS persona,
				COALESCE((SELECT group_concat(i.producto_id || ' x' || i.cantidad, ', ')
				          FROM cambio_operacion_items i
				          WHERE i.operacion_id = o.id AND i.direccion = 'salida'), o.saliente_producto_id) AS saliente_sku,
				COALESCE((SELECT group_concat(i.producto_nombre || ' x' || i.cantidad, ', ')
				          FROM cambio_operacion_items i
				          WHERE i.operacion_id = o.id AND i.direccion = 'salida'), o.saliente_producto_nombre) AS saliente_producto,
				COALESCE((SELECT SUM(i.cantidad)
				          FROM cambio_operacion_items i
				          WHERE i.operacion_id = o.id AND i.direccion = 'salida'), o.saliente_cantidad) AS saliente_cantidad,
				COALESCE((SELECT group_concat(i.producto_id || ' x' || i.cantidad, ', ')
				          FROM cambio_operacion_items i
				          WHERE i.operacion_id = o.id AND i.direccion = 'entrada'), o.entrante_producto_id) AS entrante_sku,
				COALESCE((SELECT group_concat(i.producto_nombre || ' x' || i.cantidad, ', ')
				          FROM cambio_operacion_items i
				          WHERE i.operacion_id = o.id AND i.direccion = 'entrada'), o.entrante_producto_nombre) AS entrante_producto,
				COALESCE((SELECT SUM(i.cantidad)
				          FROM cambio_operacion_items i
				          WHERE i.operacion_id = o.id AND i.direccion = 'entrada'), o.entrante_cantidad) AS entrante_cantidad,
				o.notas AS motivo,
				o.usuario
			FROM cambio_operaciones o
			WHERE date(o.fecha) BETWEEN ? AND ?
			UNION ALL
			SELECT
				c.id,
				c.updated_at AS fecha,
				c.cliente AS persona,
				COALESCE((SELECT group_concat(i.producto_id || ' x' || i.cantidad, ', ')
				          FROM checkout_cambio_items i
				          WHERE i.checkout_id = c.id AND i.direccion = 'salida' AND i.estado = 'procesada'), '-') AS saliente_sku,
				COALESCE((SELECT group_concat(i.producto_nombre || ' x' || i.cantidad, ', ')
				          FROM checkout_cambio_items i
				          WHERE i.checkout_id = c.id AND i.direccion = 'salida' AND i.estado = 'procesada'), '-') AS saliente_producto,
				COALESCE((SELECT SUM(i.cantidad)
				          FROM checkout_cambio_items i
				          WHERE i.checkout_id = c.id AND i.direccion = 'salida' AND i.estado = 'procesada'), 0) AS saliente_cantidad,
				COALESCE((SELECT group_concat(i.producto_id || ' x' || i.cantidad, ', ')
				          FROM checkout_cambio_items i
				          WHERE i.checkout_id = c.id AND i.direccion = 'entrada' AND i.estado = 'procesada'), '-') AS entrante_sku,
				COALESCE((SELECT group_concat(i.producto_nombre || ' x' || i.cantidad, ', ')
				          FROM checkout_cambio_items i
				          WHERE i.checkout_id = c.id AND i.direccion = 'entrada' AND i.estado = 'procesada'), '-') AS entrante_producto,
				COALESCE((SELECT SUM(i.cantidad)
				          FROM checkout_cambio_items i
				          WHERE i.checkout_id = c.id AND i.direccion = 'entrada' AND i.estado = 'procesada'), 0) AS entrante_cantidad,
				c.notas AS motivo,
				COALESCE(u.username, '') AS usuario
			FROM checkout_operaciones c
			LEFT JOIN users u ON u.id = c.user_id
			WHERE c.estado IN ('parcial', 'confirmado')
			  AND date(c.updated_at) BETWEEN ? AND ?
			  AND EXISTS (
				SELECT 1 FROM checkout_cambio_items i
				WHERE i.checkout_id = c.id AND i.estado = 'procesada'
			  )
		)
		ORDER BY fecha DESC, id DESC
		LIMIT 200
	`, startStr, endStr, startStr, endStr)
	if err != nil {
		return dashboardDataResponse{}, err
	}
	defer detailRows.Close()

	changes := make([]dashboardChange, 0, 32)
	for detailRows.Next() {
		var change dashboardChange
		var fechaRaw string
		if err := detailRows.Scan(
			&change.ID,
			&fechaRaw,
			&change.Persona,
			&change.SalienteSKU,
			&change.SalienteProducto,
			&change.SalienteCantidad,
			&change.EntranteSKU,
			&change.EntranteProducto,
			&change.EntranteCantidad,
			&change.Motivo,
			&change.Usuario,
		); err != nil {
			return dashboardDataResponse{}, err
		}
		change.Fecha = fechaRaw
		if len(fechaRaw) >= 10 {
			change.Fecha = fechaRaw[:10]
		}
		changes = append(changes, change)
	}
	if err := detailRows.Err(); err != nil {
		return dashboardDataResponse{}, err
	}
	resp.Changes = changes

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
	var productID, state, saleType string
	if err := tx.QueryRow(`SELECT producto_id, estado, COALESCE(tipo, 'producto') FROM ventas WHERE id = ?`, saleID).Scan(&productID, &state, &saleType); err != nil {
		if err == sql.ErrNoRows {
			return errSaleNotFound
		}
		return err
	}
	if state != "confirmada" {
		return errSaleAlreadyCancelled
	}
	if saleType == "cargo" || productID == checkoutChargeProductID {
		now := time.Now().Format(time.RFC3339)
		result, err := tx.Exec(`
			UPDATE ventas
			SET estado = 'anulada', anulada_en = ?, anulada_por = ?, anulacion_motivo = ?
			WHERE id = ? AND estado = 'confirmada'`, now, user.Username, reason, saleID)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return errSaleAlreadyCancelled
		}
		return logAudit(tx, "sale.cancel", "venta", strconv.Itoa(saleID), reason, user, now)
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

func deleteSpecificAvailableUnits(tx *sql.Tx, productID string, unitIDs []string) ([]string, error) {
	productID = strings.TrimSpace(productID)
	if productID == "" || len(unitIDs) == 0 {
		return nil, fmt.Errorf("unidades inválidas")
	}

	seen := make(map[string]struct{}, len(unitIDs))
	normalizedIDs := make([]string, 0, len(unitIDs))
	for _, id := range unitIDs {
		normalizedID := strings.TrimSpace(id)
		if normalizedID == "" {
			return nil, fmt.Errorf("unidad inválida")
		}
		if _, exists := seen[normalizedID]; exists {
			return nil, fmt.Errorf("unidad repetida")
		}
		seen[normalizedID] = struct{}{}
		normalizedIDs = append(normalizedIDs, normalizedID)
	}

	placeholders := make([]string, len(normalizedIDs))
	args := make([]any, 0, len(normalizedIDs)+1)
	args = append(args, productID)
	for i, id := range normalizedIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	query := fmt.Sprintf(`
		DELETE FROM unidades
		WHERE producto_id = ?
		  AND id IN (%s)
		  AND estado IN ('Disponible', 'available')`, strings.Join(placeholders, ","))
	result, err := tx.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("eliminar unidades seleccionadas: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("rows affected: %w", err)
	}
	if int(affected) != len(normalizedIDs) {
		return nil, errInsufficientStock
	}

	return normalizedIDs, nil
}

type cambioInventoryInput struct {
	ProductID         string
	OutgoingName      string
	OutgoingUnitIDs   []string
	IncomingProductID string
	IncomingNew       bool
	IncomingName      string
	IncomingLine      string
	IncomingQuantity  int
	PersonaCambio     string
	Notas             string
	MovementNote      string
	User              *User
	Now               string
}

type cambioLineInput struct {
	ProductoID string
	Cantidad   int
	EsNuevo    bool
	Nombre     string
	Linea      string
}

type cambioMultiInput struct {
	Salientes     []cambioLineInput
	Entrantes     []cambioLineInput
	PersonaCambio string
	Notas         string
	MovementNote  string
	User          *User
	Now           string
}

type cambioMultiResult struct {
	OperationID     int64
	SalienteUnitIDs []string
	EntranteUnitIDs []string
}

type cambioLineDraft struct {
	N                  int
	ProductoID         string
	Cantidad           int
	EsNuevo            bool
	IncomingMode       string
	IncomingExistingID string
	IncomingNewSKU     string
	IncomingNewName    string
	IncomingNewLine    string
	ErrorProducto      string
	ErrorCantidad      string
	ErrorSKU           string
	ErrorNombre        string
	ErrorLinea         string
}

type cambioConfirmLine struct {
	ProductoID     string
	ProductoNombre string
	Cantidad       int
	EsNuevo        bool
}

type cambioInventoryResult struct {
	OutgoingUnitIDs []string
	IncomingUnitIDs []string
	OperationID     int64
}

func applyCambioInventory(tx *sql.Tx, input cambioInventoryInput) (cambioInventoryResult, error) {
	productID := strings.TrimSpace(input.ProductID)
	incomingProductID := strings.TrimSpace(input.IncomingProductID)
	if productID == "" || incomingProductID == "" || len(input.OutgoingUnitIDs) == 0 ||
		len(input.OutgoingUnitIDs) > maxCambioQuantity || input.IncomingQuantity <= 0 || input.IncomingQuantity > maxCambioQuantity {
		return cambioInventoryResult{}, fmt.Errorf("datos de inventario del cambio inválidos")
	}
	if input.IncomingNew && strings.TrimSpace(input.IncomingName) == "" {
		return cambioInventoryResult{}, fmt.Errorf("nombre del producto entrante requerido")
	}

	if input.IncomingNew {
		var productCount int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = ? OR id = ?`, incomingProductID, incomingProductID).Scan(&productCount); err != nil {
			return cambioInventoryResult{}, fmt.Errorf("consultar SKU entrante: %w", err)
		}
		if productCount != 0 {
			return cambioInventoryResult{}, errCambioIncomingSKUExists
		}
	} else {
		var productCount int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = ?`, incomingProductID).Scan(&productCount); err != nil {
			return cambioInventoryResult{}, fmt.Errorf("consultar producto entrante: %w", err)
		}
		if productCount != 1 {
			return cambioInventoryResult{}, fmt.Errorf("producto entrante inexistente")
		}
	}

	outgoingName := strings.TrimSpace(input.OutgoingName)
	if outgoingName == "" {
		if err := tx.QueryRow(`SELECT nombre FROM productos WHERE sku = ?`, productID).Scan(&outgoingName); err != nil {
			return cambioInventoryResult{}, fmt.Errorf("consultar producto saliente: %w", err)
		}
	}
	incomingName := strings.TrimSpace(input.IncomingName)
	if !input.IncomingNew && incomingName == "" {
		if err := tx.QueryRow(`SELECT nombre FROM productos WHERE sku = ?`, incomingProductID).Scan(&incomingName); err != nil {
			return cambioInventoryResult{}, fmt.Errorf("consultar nombre entrante: %w", err)
		}
	}

	now := strings.TrimSpace(input.Now)
	if now == "" {
		now = time.Now().Format(time.RFC3339)
	}

	outgoingUnitIDs, err := deleteSpecificAvailableUnits(tx, productID, input.OutgoingUnitIDs)
	if err != nil {
		return cambioInventoryResult{}, err
	}
	if err := logMovimientos(tx, productID, outgoingUnitIDs, "cambio_salida", input.MovementNote, input.User, now); err != nil {
		return cambioInventoryResult{}, fmt.Errorf("registrar salida del cambio: %w", err)
	}

	if input.IncomingNew {
		line := strings.TrimSpace(input.IncomingLine)
		if line == "" {
			line = "Sin línea"
		}
		if _, err := tx.Exec(`
			INSERT INTO productos (sku, id, linea, nombre, fecha_ingreso)
			VALUES (?, ?, ?, ?, ?)`, incomingProductID, incomingProductID, line, incomingName, now); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique constraint failed") {
				return cambioInventoryResult{}, errCambioIncomingSKUExists
			}
			return cambioInventoryResult{}, fmt.Errorf("registrar producto entrante: %w", err)
		}
	}

	incomingUnitIDs := make([]string, 0, input.IncomingQuantity)
	baseID := time.Now().UnixNano()
	for i := 0; i < input.IncomingQuantity; i++ {
		unitID := fmt.Sprintf("U-%s-%d-%d", incomingProductID, baseID, i+1)
		if _, err := tx.Exec(
			`INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad)
			VALUES (?, ?, 'Disponible', ?, NULL)`,
			unitID, incomingProductID, now,
		); err != nil {
			return cambioInventoryResult{}, fmt.Errorf("registrar unidad entrante: %w", err)
		}
		incomingUnitIDs = append(incomingUnitIDs, unitID)
	}
	if err := logMovimientos(tx, incomingProductID, incomingUnitIDs, "cambio_entrada", input.MovementNote, input.User, now); err != nil {
		return cambioInventoryResult{}, fmt.Errorf("registrar entrada del cambio: %w", err)
	}
	if err := logAudit(tx, "inventory.change", "producto", productID, fmt.Sprintf("salientes=%d entrantes=%d producto_entrante=%s", len(outgoingUnitIDs), len(incomingUnitIDs), incomingProductID), input.User, now); err != nil {
		return cambioInventoryResult{}, fmt.Errorf("registrar auditoría del cambio: %w", err)
	}
	username := ""
	if input.User != nil {
		username = input.User.Username
	}
	operation, err := tx.Exec(`
		INSERT INTO cambio_operaciones (
			fecha, persona_cambio, notas,
			saliente_producto_id, saliente_producto_nombre, saliente_cantidad,
			entrante_producto_id, entrante_producto_nombre, entrante_cantidad,
			usuario
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now,
		strings.TrimSpace(input.PersonaCambio),
		strings.TrimSpace(input.Notas),
		productID,
		outgoingName,
		len(outgoingUnitIDs),
		incomingProductID,
		incomingName,
		len(incomingUnitIDs),
		username,
	)
	if err != nil {
		return cambioInventoryResult{}, fmt.Errorf("registrar operación del cambio: %w", err)
	}
	operationID, err := operation.LastInsertId()
	if err != nil {
		return cambioInventoryResult{}, fmt.Errorf("obtener operación del cambio: %w", err)
	}

	return cambioInventoryResult{
		OutgoingUnitIDs: outgoingUnitIDs,
		IncomingUnitIDs: incomingUnitIDs,
		OperationID:     operationID,
	}, nil
}

func applyCambioInventoryMulti(tx *sql.Tx, input cambioMultiInput) (cambioMultiResult, error) {
	now := strings.TrimSpace(input.Now)
	if now == "" {
		now = time.Now().Format(time.RFC3339)
	}
	persona := strings.TrimSpace(input.PersonaCambio)
	notas := strings.TrimSpace(input.Notas)
	if len(persona) > maxCambioPersonBytes || len(notas) > maxCambioNotesBytes ||
		len(input.Salientes) == 0 || len(input.Entrantes) == 0 ||
		len(input.Salientes) > maxCambioQuantity || len(input.Entrantes) > maxCambioQuantity {
		return cambioMultiResult{}, fmt.Errorf("datos del cambio inválidos")
	}

	outLines := make([]cambioLineInput, 0, len(input.Salientes))
	outSeen := make(map[string]struct{}, len(input.Salientes))
	for _, raw := range input.Salientes {
		line := raw
		line.ProductoID = strings.TrimSpace(line.ProductoID)
		if line.ProductoID == "" || len(line.ProductoID) > maxCambioSKUBytes ||
			line.Cantidad <= 0 || line.Cantidad > maxCambioQuantity {
			return cambioMultiResult{}, fmt.Errorf("datos del cambio inválidos")
		}
		if _, dup := outSeen[line.ProductoID]; dup {
			return cambioMultiResult{}, fmt.Errorf("producto saliente repetido")
		}
		outSeen[line.ProductoID] = struct{}{}
		outLines = append(outLines, line)
	}

	inLines := make([]cambioLineInput, 0, len(input.Entrantes))
	inSeen := make(map[string]struct{}, len(input.Entrantes))
	for _, raw := range input.Entrantes {
		line := raw
		line.ProductoID = strings.TrimSpace(line.ProductoID)
		line.Nombre = strings.TrimSpace(line.Nombre)
		line.Linea = strings.TrimSpace(line.Linea)
		if line.ProductoID == "" || len(line.ProductoID) > maxCambioSKUBytes ||
			line.Cantidad <= 0 || line.Cantidad > maxCambioQuantity {
			return cambioMultiResult{}, fmt.Errorf("datos del cambio inválidos")
		}
		if line.EsNuevo {
			if line.Nombre == "" || len(line.Nombre) > maxCambioNameBytes {
				return cambioMultiResult{}, fmt.Errorf("nombre del producto entrante requerido")
			}
			if len(line.Linea) > maxCambioLineBytes {
				return cambioMultiResult{}, fmt.Errorf("línea del producto entrante inválida")
			}
			if line.Linea == "" {
				line.Linea = "Sin línea"
			}
		}
		if _, dup := inSeen[line.ProductoID]; dup {
			return cambioMultiResult{}, fmt.Errorf("producto entrante repetido")
		}
		inSeen[line.ProductoID] = struct{}{}
		inLines = append(inLines, line)
	}

	for i, line := range outLines {
		var name string
		if err := tx.QueryRow(`SELECT nombre FROM productos WHERE sku = ?`, line.ProductoID).Scan(&name); err != nil {
			if err == sql.ErrNoRows {
				return cambioMultiResult{}, fmt.Errorf("producto saliente inexistente")
			}
			return cambioMultiResult{}, err
		}
		outLines[i].Nombre = name
	}
	for i, line := range inLines {
		if line.EsNuevo {
			var productCount int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = ? OR id = ?`, line.ProductoID, line.ProductoID).Scan(&productCount); err != nil {
				return cambioMultiResult{}, fmt.Errorf("consultar SKU entrante: %w", err)
			}
			if productCount != 0 {
				return cambioMultiResult{}, errCambioIncomingSKUExists
			}
		} else {
			var name string
			if err := tx.QueryRow(`SELECT nombre FROM productos WHERE sku = ?`, line.ProductoID).Scan(&name); err != nil {
				if err == sql.ErrNoRows {
					return cambioMultiResult{}, fmt.Errorf("producto entrante inexistente")
				}
				return cambioMultiResult{}, err
			}
			inLines[i].Nombre = name
		}
	}

	salienteUnitIDs := make([]string, 0)
	for _, line := range outLines {
		unitIDs, err := selectAvailableUnitIDsTx(tx, line.ProductoID, line.Cantidad)
		if err != nil {
			if err == errInsufficientStock {
				return cambioMultiResult{}, fmt.Errorf("stock insuficiente para %q", line.ProductoID)
			}
			return cambioMultiResult{}, err
		}
		if _, err := deleteSpecificAvailableUnits(tx, line.ProductoID, unitIDs); err != nil {
			return cambioMultiResult{}, err
		}
		if err := logMovimientos(tx, line.ProductoID, unitIDs, "cambio_salida", input.MovementNote, input.User, now); err != nil {
			return cambioMultiResult{}, fmt.Errorf("registrar salida del cambio: %w", err)
		}
		for _, id := range unitIDs {
			salienteUnitIDs = append(salienteUnitIDs, id)
		}
	}

	entranteUnitIDs := make([]string, 0)
	for _, line := range inLines {
		if line.EsNuevo {
			if _, err := tx.Exec(`
				INSERT INTO productos (sku, id, linea, nombre, fecha_ingreso)
				VALUES (?, ?, ?, ?, ?)`, line.ProductoID, line.ProductoID, line.Linea, line.Nombre, now); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique constraint failed") {
					return cambioMultiResult{}, errCambioIncomingSKUExists
				}
				return cambioMultiResult{}, fmt.Errorf("registrar producto entrante: %w", err)
			}
		}
		token, err := generateToken()
		if err != nil {
			return cambioMultiResult{}, err
		}
		unitIDs := make([]string, 0, line.Cantidad)
		for i := 1; i <= line.Cantidad; i++ {
			unitID := newCheckoutUnitID(line.ProductoID, token, i)
			if _, err := tx.Exec(
				`INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad)
				VALUES (?, ?, 'Disponible', ?, NULL)`,
				unitID, line.ProductoID, now,
			); err != nil {
				return cambioMultiResult{}, fmt.Errorf("registrar unidad entrante: %w", err)
			}
			unitIDs = append(unitIDs, unitID)
		}
		if err := logMovimientos(tx, line.ProductoID, unitIDs, "cambio_entrada", input.MovementNote, input.User, now); err != nil {
			return cambioMultiResult{}, fmt.Errorf("registrar entrada del cambio: %w", err)
		}
		for _, id := range unitIDs {
			entranteUnitIDs = append(entranteUnitIDs, id)
		}
	}

	firstOut := outLines[0]
	firstIn := inLines[0]
	username := ""
	if input.User != nil {
		username = input.User.Username
	}
	operation, err := tx.Exec(`
		INSERT INTO cambio_operaciones (
			fecha, persona_cambio, notas,
			saliente_producto_id, saliente_producto_nombre, saliente_cantidad,
			entrante_producto_id, entrante_producto_nombre, entrante_cantidad,
			usuario
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now,
		persona,
		notas,
		firstOut.ProductoID,
		firstOut.Nombre,
		firstOut.Cantidad,
		firstIn.ProductoID,
		firstIn.Nombre,
		firstIn.Cantidad,
		username,
	)
	if err != nil {
		return cambioMultiResult{}, fmt.Errorf("registrar operación del cambio: %w", err)
	}
	operationID, err := operation.LastInsertId()
	if err != nil {
		return cambioMultiResult{}, fmt.Errorf("obtener operación del cambio: %w", err)
	}

	order := 0
	for _, line := range outLines {
		order++
		if _, err := tx.Exec(`
			INSERT INTO cambio_operacion_items (
				operacion_id, direccion, producto_id, producto_nombre, linea,
				cantidad, es_nuevo, orden
			)
			VALUES (?, 'salida', ?, ?, '', ?, 0, ?)`,
			operationID, line.ProductoID, line.Nombre, line.Cantidad, order); err != nil {
			return cambioMultiResult{}, fmt.Errorf("registrar línea de salida: %w", err)
		}
	}
	for _, line := range inLines {
		order++
		if _, err := tx.Exec(`
			INSERT INTO cambio_operacion_items (
				operacion_id, direccion, producto_id, producto_nombre, linea,
				cantidad, es_nuevo, orden
			)
			VALUES (?, 'entrada', ?, ?, ?, ?, ?, ?)`,
			operationID, line.ProductoID, line.Nombre, line.Linea, line.Cantidad, boolToInt(line.EsNuevo), order); err != nil {
			return cambioMultiResult{}, fmt.Errorf("registrar línea de entrada: %w", err)
		}
	}

	if err := logAudit(tx, "inventory.change", "producto", firstOut.ProductoID,
		fmt.Sprintf("operacion=%d salientes=%d lineas=%d entrantes=%d lineas=%d",
			operationID, len(salienteUnitIDs), len(outLines), len(entranteUnitIDs), len(inLines)),
		input.User, now); err != nil {
		return cambioMultiResult{}, fmt.Errorf("registrar auditoría del cambio: %w", err)
	}

	return cambioMultiResult{
		OperationID:     operationID,
		SalienteUnitIDs: salienteUnitIDs,
		EntranteUnitIDs: entranteUnitIDs,
	}, nil
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

type checkoutBusinessError struct {
	message string
}

func (e *checkoutBusinessError) Error() string { return e.message }

func checkoutBusinessErrorf(format string, args ...any) error {
	return &checkoutBusinessError{message: fmt.Sprintf(format, args...)}
}

func isCheckoutBusinessError(err error) bool {
	if errors.Is(err, errInsufficientStock) {
		return true
	}
	var businessErr *checkoutBusinessError
	return errors.As(err, &businessErr)
}

func maxMoneyValue() int64 {
	return int64(^uint64(0) >> 1)
}

func multiplyCOP(unitPrice int64, quantity int) (int64, error) {
	if unitPrice <= 0 || quantity <= 0 {
		return 0, checkoutBusinessErrorf("El importe y la cantidad deben ser válidos.")
	}
	if int64(quantity) > maxMoneyValue()/unitPrice {
		return 0, checkoutBusinessErrorf("El total de la línea es demasiado grande.")
	}
	return unitPrice * int64(quantity), nil
}

func checkoutText(value, label string, maxBytes int) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > maxBytes {
		return "", checkoutBusinessErrorf("%s supera el máximo permitido.", label)
	}
	return value, nil
}

func ensureCheckoutTx(tx *sql.Tx, userID int) (int64, error) {
	if userID <= 0 {
		return 0, fmt.Errorf("usuario de checkout inválido")
	}
	var checkoutID int64
	err := tx.QueryRow(`
		SELECT id
		FROM checkout_operaciones
		WHERE user_id = ? AND estado IN ('borrador', 'parcial')
		ORDER BY id
		LIMIT 1`, userID).Scan(&checkoutID)
	if err == nil {
		return checkoutID, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}

	now := time.Now().Format(time.RFC3339)
	if _, err := tx.Exec(`
		INSERT OR IGNORE INTO checkout_operaciones
			(user_id, estado, created_at, updated_at)
		VALUES (?, 'borrador', ?, ?)`, userID, now, now); err != nil {
		return 0, err
	}
	if err := tx.QueryRow(`
		SELECT id
		FROM checkout_operaciones
		WHERE user_id = ? AND estado IN ('borrador', 'parcial')
		ORDER BY id
		LIMIT 1`, userID).Scan(&checkoutID); err != nil {
		return 0, err
	}
	return checkoutID, nil
}

func ensureActiveCheckout(db *sql.DB, userID int) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	checkoutID, err := ensureCheckoutTx(tx, userID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	committed = true
	return checkoutID, nil
}

func nextCheckoutOrderTx(tx *sql.Tx, checkoutID int64) (int, error) {
	var next int
	if err := tx.QueryRow(`
		SELECT COALESCE(MAX(orden), 0) + 1
		FROM (
			SELECT orden FROM checkout_venta_items WHERE checkout_id = ?
			UNION ALL
			SELECT orden FROM checkout_cambio_items WHERE checkout_id = ?
		)`, checkoutID, checkoutID).Scan(&next); err != nil {
		return 0, err
	}
	return next, nil
}

func touchCheckoutTx(tx *sql.Tx, checkoutID int64, now string) error {
	_, err := tx.Exec(`UPDATE checkout_operaciones SET updated_at = ? WHERE id = ?`, now, checkoutID)
	return err
}

func productSalePriceTx(tx *sql.Tx, productID string) (string, int64, error) {
	var name string
	var price int64
	err := tx.QueryRow(`
		SELECT nombre,
		       CASE WHEN COALESCE(precio_venta_cop, 0) <> 0
		            THEN precio_venta_cop
		            ELSE CAST(ROUND(COALESCE(precio_venta, 0)) AS INTEGER)
		       END
		FROM productos
		WHERE sku = ?`, productID).Scan(&name, &price)
	if err == sql.ErrNoRows {
		return "", 0, checkoutBusinessErrorf("El producto seleccionado no existe.")
	}
	if err != nil {
		return "", 0, err
	}
	return name, price, nil
}

func addCheckoutSaleItem(db *sql.DB, userID int, input checkoutSaleInput) (int64, error) {
	input.Tipo = strings.TrimSpace(input.Tipo)
	if input.Tipo == "" {
		input.Tipo = "producto"
	}
	if input.Tipo != "producto" && input.Tipo != "cargo" {
		return 0, checkoutBusinessErrorf("Tipo de línea de venta inválido.")
	}
	if input.Tipo == "producto" && input.Cantidad <= 0 {
		return 0, checkoutBusinessErrorf("La cantidad debe ser positiva.")
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	checkoutID, err := ensureCheckoutTx(tx, userID)
	if err != nil {
		return 0, err
	}
	if input.Tipo == "cargo" {
		if input.TotalCOP <= 0 {
			return 0, checkoutBusinessErrorf("El cargo debe tener un valor mayor a cero.")
		}
		input.ProductoID = checkoutChargeProductID
		input.ProductoNombre = "Diferencia de cambio"
		input.Cantidad = 1
		input.PrecioUnitarioCOP = input.TotalCOP
	} else {
		var textErr error
		input.ProductoID, textErr = checkoutText(input.ProductoID, "El SKU", 80)
		if textErr != nil {
			return 0, textErr
		}
		if input.ProductoID == "" {
			return 0, checkoutBusinessErrorf("Selecciona un producto válido.")
		}
		name, catalogPrice, err := productSalePriceTx(tx, input.ProductoID)
		if err != nil {
			return 0, err
		}
		input.ProductoNombre = name
		if input.PrecioUnitarioCOP <= 0 {
			input.PrecioUnitarioCOP = catalogPrice
		}
		if input.PrecioUnitarioCOP <= 0 {
			return 0, checkoutBusinessErrorf("El producto no tiene un precio de venta válido.")
		}
	}
	var textErr error
	input.Notas, textErr = checkoutText(input.Notas, "Las notas", 500)
	if textErr != nil {
		return 0, textErr
	}

	total, err := multiplyCOP(input.PrecioUnitarioCOP, input.Cantidad)
	if err != nil {
		return 0, err
	}
	order, err := nextCheckoutOrderTx(tx, checkoutID)
	if err != nil {
		return 0, err
	}
	now := time.Now().Format(time.RFC3339)
	result, err := tx.Exec(`
		INSERT INTO checkout_venta_items (
			checkout_id, tipo, producto_id, producto_nombre, cantidad,
			precio_unitario_cop, total_cop, notas, orden, estado,
			created_at, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pendiente', ?, ?)`,
		checkoutID,
		input.Tipo,
		input.ProductoID,
		strings.TrimSpace(input.ProductoNombre),
		input.Cantidad,
		input.PrecioUnitarioCOP,
		total,
		strings.TrimSpace(input.Notas),
		order,
		now,
		now,
	)
	if err != nil {
		return 0, err
	}
	itemID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := touchCheckoutTx(tx, checkoutID, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	committed = true
	return itemID, nil
}

func normalizeCheckoutChangeInput(input checkoutChangeInput) (checkoutChangeInput, error) {
	input.Direccion = strings.TrimSpace(input.Direccion)
	if input.Direccion != "salida" && input.Direccion != "entrada" {
		return checkoutChangeInput{}, checkoutBusinessErrorf("Dirección de cambio inválida.")
	}
	if input.Cantidad <= 0 {
		return checkoutChangeInput{}, checkoutBusinessErrorf("La cantidad debe ser positiva.")
	}
	if input.Cantidad > maxCambioQuantity {
		return checkoutChangeInput{}, checkoutBusinessErrorf("La cantidad no puede superar 10.000 unidades.")
	}
	var textErr error
	input.ProductoID, textErr = checkoutText(input.ProductoID, "El SKU", maxCambioSKUBytes)
	if textErr != nil {
		return checkoutChangeInput{}, textErr
	}
	if input.ProductoID == "" {
		return checkoutChangeInput{}, checkoutBusinessErrorf("Selecciona un producto válido.")
	}
	if input.Direccion == "entrada" && input.EsNuevo {
		input.ProductoNombre, textErr = checkoutText(input.ProductoNombre, "El nombre del producto", maxCambioNameBytes)
		if textErr != nil {
			return checkoutChangeInput{}, textErr
		}
		if input.ProductoNombre == "" {
			return checkoutChangeInput{}, checkoutBusinessErrorf("El nombre del producto entrante es obligatorio.")
		}
		input.Linea, textErr = checkoutText(input.Linea, "La línea del producto", maxCambioLineBytes)
		if textErr != nil {
			return checkoutChangeInput{}, textErr
		}
		if input.Linea == "" {
			input.Linea = "Sin línea"
		}
	}
	return input, nil
}

func insertCheckoutChangeItemTx(tx *sql.Tx, checkoutID int64, input checkoutChangeInput, now string) (int64, error) {
	if input.Direccion == "salida" {
		name, _, err := productSalePriceTx(tx, input.ProductoID)
		if err != nil {
			return 0, err
		}
		input.ProductoNombre = name
		input.EsNuevo = false
	} else if input.Direccion == "entrada" && input.EsNuevo {
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = ? OR id = ?`, input.ProductoID, input.ProductoID).Scan(&count); err != nil {
			return 0, err
		}
		if count > 0 {
			return 0, checkoutBusinessErrorf("El SKU del producto entrante ya existe.")
		}
	} else if input.Direccion == "entrada" {
		name, _, err := productSalePriceTx(tx, input.ProductoID)
		if err != nil {
			return 0, err
		}
		input.ProductoNombre = name
		input.Linea = ""
	} else {
		return 0, checkoutBusinessErrorf("Dirección de cambio inválida.")
	}

	order, err := nextCheckoutOrderTx(tx, checkoutID)
	if err != nil {
		return 0, err
	}
	result, err := tx.Exec(`
		INSERT INTO checkout_cambio_items (
			checkout_id, direccion, producto_id, producto_nombre, linea,
			cantidad, es_nuevo, orden, estado, created_at, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pendiente', ?, ?)`,
		checkoutID,
		input.Direccion,
		input.ProductoID,
		strings.TrimSpace(input.ProductoNombre),
		strings.TrimSpace(input.Linea),
		input.Cantidad,
		boolToInt(input.EsNuevo),
		order,
		now,
		now,
	)
	if err != nil {
		return 0, err
	}
	itemID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := touchCheckoutTx(tx, checkoutID, now); err != nil {
		return 0, err
	}
	return itemID, nil
}

func addCheckoutChangeItem(db *sql.DB, userID int, input checkoutChangeInput) (int64, error) {
	input, err := normalizeCheckoutChangeInput(input)
	if err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	checkoutID, err := ensureCheckoutTx(tx, userID)
	if err != nil {
		return 0, err
	}
	itemID, err := insertCheckoutChangeItemTx(tx, checkoutID, input, time.Now().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	committed = true
	return itemID, nil
}

func addCheckoutChangePair(db *sql.DB, userID int, outgoing, incoming checkoutChangeInput) error {
	outgoing, err := normalizeCheckoutChangeInput(outgoing)
	if err != nil {
		return err
	}
	incoming, err = normalizeCheckoutChangeInput(incoming)
	if err != nil {
		return err
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

	checkoutID, err := ensureCheckoutTx(tx, userID)
	if err != nil {
		return err
	}
	now := time.Now().Format(time.RFC3339)
	if _, err := insertCheckoutChangeItemTx(tx, checkoutID, outgoing, now); err != nil {
		return err
	}
	if _, err := insertCheckoutChangeItemTx(tx, checkoutID, incoming, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func loadActiveCheckout(db *sql.DB, userID int) (checkoutOperation, []checkoutSaleItem, []checkoutChangeItem, error) {
	checkoutID, err := ensureActiveCheckout(db, userID)
	if err != nil {
		return checkoutOperation{}, nil, nil, err
	}
	var checkout checkoutOperation
	if err := db.QueryRow(`
		SELECT id, user_id, cliente, metodo_pago, notas, estado, total_cop, created_at, updated_at
		FROM checkout_operaciones
		WHERE id = ? AND user_id = ?`, checkoutID, userID).Scan(
		&checkout.ID,
		&checkout.UserID,
		&checkout.Cliente,
		&checkout.MetodoPago,
		&checkout.Notas,
		&checkout.Estado,
		&checkout.TotalCOP,
		&checkout.CreatedAt,
		&checkout.UpdatedAt,
	); err != nil {
		return checkoutOperation{}, nil, nil, err
	}
	checkout.TotalText = formatCurrency(checkout.TotalCOP)

	saleRows, err := db.Query(`
		SELECT id, checkout_id, tipo, producto_id, producto_nombre, cantidad,
		       precio_unitario_cop, total_cop, notas, orden, estado, error,
		       venta_id, created_at, updated_at
		FROM checkout_venta_items
		WHERE checkout_id = ?
		ORDER BY orden, id`, checkoutID)
	if err != nil {
		return checkoutOperation{}, nil, nil, err
	}
	sales := make([]checkoutSaleItem, 0)
	for saleRows.Next() {
		var item checkoutSaleItem
		if err := saleRows.Scan(
			&item.ID,
			&item.CheckoutID,
			&item.Tipo,
			&item.ProductoID,
			&item.ProductoNombre,
			&item.Cantidad,
			&item.PrecioUnitarioCOP,
			&item.TotalCOP,
			&item.Notas,
			&item.Orden,
			&item.Estado,
			&item.Error,
			&item.VentaID,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			saleRows.Close()
			return checkoutOperation{}, nil, nil, err
		}
		item.PrecioText = formatCurrency(item.PrecioUnitarioCOP)
		item.TotalText = formatCurrency(item.TotalCOP)
		sales = append(sales, item)
	}
	if err := saleRows.Err(); err != nil {
		saleRows.Close()
		return checkoutOperation{}, nil, nil, err
	}
	saleRows.Close()

	changeRows, err := db.Query(`
		SELECT id, checkout_id, direccion, producto_id, producto_nombre, linea,
		       cantidad, es_nuevo, orden, estado, error, processed_at,
		       created_at, updated_at
		FROM checkout_cambio_items
		WHERE checkout_id = ?
		ORDER BY orden, id`, checkoutID)
	if err != nil {
		return checkoutOperation{}, nil, nil, err
	}
	changes := make([]checkoutChangeItem, 0)
	for changeRows.Next() {
		var item checkoutChangeItem
		var isNew int
		if err := changeRows.Scan(
			&item.ID,
			&item.CheckoutID,
			&item.Direccion,
			&item.ProductoID,
			&item.ProductoNombre,
			&item.Linea,
			&item.Cantidad,
			&isNew,
			&item.Orden,
			&item.Estado,
			&item.Error,
			&item.ProcessedAt,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			changeRows.Close()
			return checkoutOperation{}, nil, nil, err
		}
		item.EsNuevo = isNew == 1
		changes = append(changes, item)
	}
	if err := changeRows.Err(); err != nil {
		changeRows.Close()
		return checkoutOperation{}, nil, nil, err
	}
	changeRows.Close()

	for _, item := range sales {
		if item.Estado != checkoutLineDiscarded {
			checkout.ItemCount++
		}
	}
	for _, item := range changes {
		if item.Estado != checkoutLineDiscarded {
			checkout.ItemCount++
		}
	}
	for _, item := range sales {
		if item.Estado == checkoutLinePending || item.Estado == checkoutLineError {
			checkout.PendingCount++
		}
	}
	for _, item := range changes {
		if item.Estado == checkoutLinePending || item.Estado == checkoutLineError {
			checkout.PendingCount++
		}
	}
	return checkout, sales, changes, nil
}

func selectAvailableUnitIDsTx(tx *sql.Tx, productID string, quantity int) ([]string, error) {
	if quantity <= 0 {
		return nil, checkoutBusinessErrorf("La cantidad debe ser positiva.")
	}
	rows, err := tx.Query(`
		SELECT id
		FROM unidades
		WHERE producto_id = ? AND estado IN ('Disponible', 'available')
		ORDER BY creado_en, id
		LIMIT ?`, productID, quantity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, quantity)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) != quantity {
		return nil, errInsufficientStock
	}
	return ids, nil
}

func newCheckoutUnitID(productID, token string, index int) string {
	return fmt.Sprintf("U-%s-%s-%d", productID, token, index)
}

func applyCheckoutSaleItem(tx *sql.Tx, item checkoutSaleItem, checkoutID int64, paymentMethod string, user *User, now string) (int64, error) {
	expectedTotal, err := multiplyCOP(item.PrecioUnitarioCOP, item.Cantidad)
	if err != nil || expectedTotal != item.TotalCOP {
		return 0, checkoutBusinessErrorf("El importe de la línea de venta ya no es válido.")
	}
	if item.Tipo == "cargo" {
		if item.Cantidad != 1 || item.TotalCOP <= 0 {
			return 0, checkoutBusinessErrorf("El cargo debe tener un valor mayor a cero.")
		}
		result, err := tx.Exec(`
			INSERT INTO ventas (
				producto_id, producto_nombre, tipo, cantidad, precio_final,
				metodo_pago, notas, fecha, precio_unitario_cop, total_cop, checkout_id
			)
			VALUES (?, ?, 'cargo', 1, ?, ?, ?, ?, ?, ?, ?)`,
			checkoutChargeProductID,
			"Diferencia de cambio",
			float64(item.TotalCOP),
			paymentMethod,
			strings.TrimSpace(item.Notas),
			now,
			item.TotalCOP,
			item.TotalCOP,
			checkoutID,
		)
		if err != nil {
			return 0, err
		}
		saleID, err := result.LastInsertId()
		if err != nil {
			return 0, err
		}
		if err := logAudit(tx, "sale.charge", "venta", strconv.FormatInt(saleID, 10), fmt.Sprintf("checkout=%d", checkoutID), user, now); err != nil {
			return 0, err
		}
		return saleID, nil
	}

	productID := strings.TrimSpace(item.ProductoID)
	if productID == "" {
		return 0, checkoutBusinessErrorf("La línea de venta no tiene producto.")
	}
	if _, _, err := productSalePriceTx(tx, productID); err != nil {
		return 0, err
	}
	unitIDs, err := selectAndMarkUnitsSold(tx, productID, item.Cantidad)
	if err != nil {
		if errors.Is(err, errInsufficientStock) {
			return 0, errInsufficientStock
		}
		return 0, err
	}
	if err := logMovimientos(tx, productID, unitIDs, "venta", item.Notas, user, now); err != nil {
		return 0, err
	}
	result, err := tx.Exec(`
		INSERT INTO ventas (
			producto_id, producto_nombre, tipo, cantidad, precio_final,
			metodo_pago, notas, fecha, precio_unitario_cop, total_cop, checkout_id
		)
		VALUES (?, ?, 'producto', ?, ?, ?, ?, ?, ?, ?, ?)`,
		productID,
		strings.TrimSpace(item.ProductoNombre),
		item.Cantidad,
		float64(item.PrecioUnitarioCOP),
		paymentMethod,
		strings.TrimSpace(item.Notas),
		now,
		item.PrecioUnitarioCOP,
		item.TotalCOP,
		checkoutID,
	)
	if err != nil {
		return 0, err
	}
	saleID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, unitID := range unitIDs {
		if _, err := tx.Exec(`INSERT INTO venta_unidades (venta_id, unidad_id) VALUES (?, ?)`, saleID, unitID); err != nil {
			return 0, err
		}
	}
	if err := logAudit(tx, "sale.create", "venta", strconv.FormatInt(saleID, 10), fmt.Sprintf("checkout=%d", checkoutID), user, now); err != nil {
		return 0, err
	}
	return saleID, nil
}

func applyCheckoutChangeItem(tx *sql.Tx, item checkoutChangeItem, checkoutID int64, user *User, now string) error {
	productID := strings.TrimSpace(item.ProductoID)
	if productID == "" || item.Cantidad <= 0 {
		return checkoutBusinessErrorf("La línea de cambio no es válida.")
	}
	note := fmt.Sprintf("checkout=%d", checkoutID)
	if item.Direccion == "salida" {
		if _, _, err := productSalePriceTx(tx, productID); err != nil {
			return err
		}
		unitIDs, err := selectAvailableUnitIDsTx(tx, productID, item.Cantidad)
		if err != nil {
			return err
		}
		if _, err := deleteSpecificAvailableUnits(tx, productID, unitIDs); err != nil {
			return err
		}
		if err := logMovimientos(tx, productID, unitIDs, "cambio_salida", note, user, now); err != nil {
			return err
		}
		return logAudit(tx, "inventory.change.out", "producto", productID, note, user, now)
	}

	if item.Direccion != "entrada" {
		return checkoutBusinessErrorf("Dirección de cambio inválida.")
	}
	incomingName := strings.TrimSpace(item.ProductoNombre)
	if item.EsNuevo {
		if incomingName == "" {
			return checkoutBusinessErrorf("El nombre del producto entrante es obligatorio.")
		}
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = ?`, productID).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return checkoutBusinessErrorf("El SKU del producto entrante ya existe.")
		}
		line := strings.TrimSpace(item.Linea)
		if line == "" {
			line = "Sin línea"
		}
		if _, err := tx.Exec(`
			INSERT INTO productos (sku, id, linea, nombre, fecha_ingreso)
			VALUES (?, ?, ?, ?, ?)`, productID, productID, line, incomingName, now); err != nil {
			return err
		}
	} else {
		var catalogName string
		if err := tx.QueryRow(`SELECT nombre FROM productos WHERE sku = ?`, productID).Scan(&catalogName); err != nil {
			if err == sql.ErrNoRows {
				return checkoutBusinessErrorf("El producto entrante ya no existe.")
			}
			return err
		}
		if incomingName == "" {
			incomingName = catalogName
		}
	}

	token, err := generateToken()
	if err != nil {
		return err
	}
	unitIDs := make([]string, 0, item.Cantidad)
	for i := 1; i <= item.Cantidad; i++ {
		unitID := newCheckoutUnitID(productID, token, i)
		if _, err := tx.Exec(`
			INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad)
			VALUES (?, ?, 'Disponible', ?, NULL)`, unitID, productID, now); err != nil {
			return err
		}
		unitIDs = append(unitIDs, unitID)
	}
	if err := logMovimientos(tx, productID, unitIDs, "cambio_entrada", note, user, now); err != nil {
		return err
	}
	return logAudit(tx, "inventory.change.in", "producto", productID, note, user, now)
}

func checkoutItemRefsTx(tx *sql.Tx, checkoutID int64) ([]checkoutItemRef, error) {
	rows, err := tx.Query(`
		SELECT id, 'venta', orden
		FROM checkout_venta_items
		WHERE checkout_id = ? AND estado IN ('pendiente', 'error')
		UNION ALL
		SELECT id, 'cambio', orden
		FROM checkout_cambio_items
		WHERE checkout_id = ? AND estado IN ('pendiente', 'error')
		ORDER BY orden, id`, checkoutID, checkoutID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make([]checkoutItemRef, 0)
	for rows.Next() {
		var ref checkoutItemRef
		if err := rows.Scan(&ref.ID, &ref.Kind, &ref.Order); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}

func loadCheckoutSaleItemTx(tx *sql.Tx, itemID int64) (checkoutSaleItem, error) {
	var item checkoutSaleItem
	err := tx.QueryRow(`
		SELECT id, checkout_id, tipo, producto_id, producto_nombre, cantidad,
		       precio_unitario_cop, total_cop, notas, orden, estado, error,
		       venta_id, created_at, updated_at
		FROM checkout_venta_items
		WHERE id = ?`, itemID).Scan(
		&item.ID,
		&item.CheckoutID,
		&item.Tipo,
		&item.ProductoID,
		&item.ProductoNombre,
		&item.Cantidad,
		&item.PrecioUnitarioCOP,
		&item.TotalCOP,
		&item.Notas,
		&item.Orden,
		&item.Estado,
		&item.Error,
		&item.VentaID,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	return item, err
}

func loadCheckoutChangeItemTx(tx *sql.Tx, itemID int64) (checkoutChangeItem, error) {
	var item checkoutChangeItem
	var isNew int
	err := tx.QueryRow(`
		SELECT id, checkout_id, direccion, producto_id, producto_nombre, linea,
		       cantidad, es_nuevo, orden, estado, error, processed_at,
		       created_at, updated_at
		FROM checkout_cambio_items
		WHERE id = ?`, itemID).Scan(
		&item.ID,
		&item.CheckoutID,
		&item.Direccion,
		&item.ProductoID,
		&item.ProductoNombre,
		&item.Linea,
		&item.Cantidad,
		&isNew,
		&item.Orden,
		&item.Estado,
		&item.Error,
		&item.ProcessedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	item.EsNuevo = isNew == 1
	return item, err
}

func processCheckout(db *sql.DB, userID int, checkoutID int64, cliente, paymentMethod, notes string, user *User) (checkoutProcessResult, error) {
	result := checkoutProcessResult{CheckoutID: checkoutID}
	var textErr error
	cliente, textErr = checkoutText(cliente, "El nombre del cliente", 160)
	if textErr != nil {
		return result, textErr
	}
	paymentMethod = strings.TrimSpace(paymentMethod)
	notes, textErr = checkoutText(notes, "Las notas", 2000)
	if textErr != nil {
		return result, textErr
	}
	if cliente == "" {
		return result, checkoutBusinessErrorf("El nombre del cliente es obligatorio.")
	}
	if paymentMethod == "" {
		return result, checkoutBusinessErrorf("Selecciona un método de pago.")
	}

	tx, err := db.Begin()
	if err != nil {
		return result, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var state, storedPaymentMethod string
	var ownerID int
	if err := tx.QueryRow(`SELECT user_id, estado, metodo_pago FROM checkout_operaciones WHERE id = ?`, checkoutID).Scan(&ownerID, &state, &storedPaymentMethod); err != nil {
		return result, err
	}
	if ownerID != userID {
		return result, checkoutBusinessErrorf("El checkout no pertenece al usuario actual.")
	}
	if state != checkoutStateDraft && state != checkoutStatePartial {
		return result, checkoutBusinessErrorf("El checkout ya no está disponible para confirmar.")
	}
	if state == checkoutStatePartial && strings.TrimSpace(storedPaymentMethod) != "" && storedPaymentMethod != paymentMethod {
		return result, checkoutBusinessErrorf("El método de pago no puede cambiarse después de un procesamiento parcial.")
	}
	if _, err := tx.Exec(`
		UPDATE checkout_operaciones
		SET cliente = ?, metodo_pago = ?, notas = ?, updated_at = ?
		WHERE id = ?`, cliente, paymentMethod, strings.TrimSpace(notes), time.Now().Format(time.RFC3339), checkoutID); err != nil {
		return result, err
	}

	refs, err := checkoutItemRefsTx(tx, checkoutID)
	if err != nil {
		return result, err
	}
	if len(refs) == 0 {
		return result, checkoutBusinessErrorf("Agrega al menos una línea al carrito.")
	}

	for index, ref := range refs {
		savepoint := fmt.Sprintf("checkout_line_%d", index)
		if _, err := tx.Exec("SAVEPOINT " + savepoint); err != nil {
			return result, err
		}
		var lineErr error
		var saleID int64
		var lineTotal int64
		if ref.Kind == "venta" {
			var item checkoutSaleItem
			item, lineErr = loadCheckoutSaleItemTx(tx, ref.ID)
			lineTotal = item.TotalCOP
			if lineErr == nil {
				saleID, lineErr = applyCheckoutSaleItem(tx, item, checkoutID, paymentMethod, user, time.Now().Format(time.RFC3339))
			}
		} else {
			var item checkoutChangeItem
			item, lineErr = loadCheckoutChangeItemTx(tx, ref.ID)
			if lineErr == nil {
				lineErr = applyCheckoutChangeItem(tx, item, checkoutID, user, time.Now().Format(time.RFC3339))
			}
		}

		if lineErr != nil {
			if !isCheckoutBusinessError(lineErr) {
				return result, lineErr
			}
			if _, err := tx.Exec("ROLLBACK TO SAVEPOINT " + savepoint); err != nil {
				return result, err
			}
			if _, err := tx.Exec("RELEASE SAVEPOINT " + savepoint); err != nil {
				return result, err
			}
			now := time.Now().Format(time.RFC3339)
			if ref.Kind == "venta" {
				if _, err := tx.Exec(`UPDATE checkout_venta_items SET estado = 'error', error = ?, updated_at = ? WHERE id = ? AND checkout_id = ?`, lineErr.Error(), now, ref.ID, checkoutID); err != nil {
					return result, err
				}
			} else if _, err := tx.Exec(`UPDATE checkout_cambio_items SET estado = 'error', error = ?, updated_at = ? WHERE id = ? AND checkout_id = ?`, lineErr.Error(), now, ref.ID, checkoutID); err != nil {
				return result, err
			}
			result.FailedCount++
			result.Errors = append(result.Errors, lineErr.Error())
			continue
		}

		if _, err := tx.Exec("RELEASE SAVEPOINT " + savepoint); err != nil {
			return result, err
		}
		now := time.Now().Format(time.RFC3339)
		if ref.Kind == "venta" {
			if _, err := tx.Exec(`
				UPDATE checkout_venta_items
				SET estado = 'procesada', error = '', venta_id = ?, updated_at = ?
				WHERE id = ? AND checkout_id = ?`, saleID, now, ref.ID, checkoutID); err != nil {
				return result, err
			}
			result.ProcessedTotalCOP += lineTotal
		} else if _, err := tx.Exec(`
			UPDATE checkout_cambio_items
			SET estado = 'procesada', error = '', processed_at = ?, updated_at = ?
			WHERE id = ? AND checkout_id = ?`, now, now, ref.ID, checkoutID); err != nil {
			return result, err
		}
		result.ProcessedCount++
	}

	var pending, failed int
	if err := tx.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM checkout_venta_items WHERE checkout_id = ? AND estado IN ('pendiente', 'error')) +
			(SELECT COUNT(*) FROM checkout_cambio_items WHERE checkout_id = ? AND estado IN ('pendiente', 'error')),
			(SELECT COUNT(*) FROM checkout_venta_items WHERE checkout_id = ? AND estado = 'error') +
			(SELECT COUNT(*) FROM checkout_cambio_items WHERE checkout_id = ? AND estado = 'error')`,
		checkoutID, checkoutID, checkoutID, checkoutID).Scan(&pending, &failed); err != nil {
		return result, err
	}
	result.PendingCount = pending
	result.FailedCount = failed
	result.State = checkoutStateConfirmed
	if pending > 0 {
		result.State = checkoutStatePartial
	}
	var processedTotal int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(total_cop), 0) FROM checkout_venta_items WHERE checkout_id = ? AND estado = 'procesada'`, checkoutID).Scan(&processedTotal); err != nil {
		return result, err
	}
	result.ProcessedTotalCOP = processedTotal
	if _, err := tx.Exec(`
		UPDATE checkout_operaciones
		SET estado = ?, total_cop = ?, updated_at = ?
		WHERE id = ? AND user_id = ?`, result.State, processedTotal, time.Now().Format(time.RFC3339), checkoutID, userID); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	committed = true
	return result, nil
}

func updateCheckoutDetails(db *sql.DB, userID int, cliente, paymentMethod, notes string) error {
	var textErr error
	cliente, textErr = checkoutText(cliente, "El nombre del cliente", 160)
	if textErr != nil {
		return textErr
	}
	notes, textErr = checkoutText(notes, "Las notas", 2000)
	if textErr != nil {
		return textErr
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
	checkoutID, err := ensureCheckoutTx(tx, userID)
	if err != nil {
		return err
	}
	var storedPaymentMethod string
	var processedSales int
	if err := tx.QueryRow(`SELECT metodo_pago FROM checkout_operaciones WHERE id = ?`, checkoutID).Scan(&storedPaymentMethod); err != nil {
		return err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM checkout_venta_items WHERE checkout_id = ? AND estado = 'procesada'`, checkoutID).Scan(&processedSales); err != nil {
		return err
	}
	if processedSales > 0 && strings.TrimSpace(storedPaymentMethod) != "" && strings.TrimSpace(paymentMethod) != storedPaymentMethod {
		return checkoutBusinessErrorf("El método de pago no puede cambiarse después de un procesamiento parcial.")
	}
	if _, err := tx.Exec(`
		UPDATE checkout_operaciones
		SET cliente = ?, metodo_pago = ?, notas = ?, updated_at = ?
		WHERE id = ? AND user_id = ? AND estado IN ('borrador', 'parcial')`,
		strings.TrimSpace(cliente), strings.TrimSpace(paymentMethod), strings.TrimSpace(notes), time.Now().Format(time.RFC3339), checkoutID, userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func updateCheckoutSaleItem(db *sql.DB, userID int, itemID int64, quantity int, unitPrice int64, notes string) error {
	if quantity <= 0 || unitPrice <= 0 {
		return checkoutBusinessErrorf("La cantidad y el precio deben ser mayores a cero.")
	}
	var textErr error
	notes, textErr = checkoutText(notes, "Las notas", 500)
	if textErr != nil {
		return textErr
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
	var checkoutID int64
	var kind, productID, productName string
	if err := tx.QueryRow(`
		SELECT i.checkout_id, i.tipo, i.producto_id, i.producto_nombre
		FROM checkout_venta_items i
		JOIN checkout_operaciones c ON c.id = i.checkout_id
		WHERE i.id = ? AND c.user_id = ? AND c.estado IN ('borrador', 'parcial')
		  AND i.estado IN ('pendiente', 'error')`, itemID, userID).Scan(&checkoutID, &kind, &productID, &productName); err != nil {
		if err == sql.ErrNoRows {
			return checkoutBusinessErrorf("La línea de venta ya no está disponible para editar.")
		}
		return err
	}
	if kind == "cargo" {
		quantity = 1
		productID = checkoutChargeProductID
		productName = "Diferencia de cambio"
	}
	if kind == "producto" {
		name, _, err := productSalePriceTx(tx, productID)
		if err != nil {
			return err
		}
		if productName == "" {
			productName = name
		}
	}
	total, err := multiplyCOP(unitPrice, quantity)
	if err != nil {
		return err
	}
	now := time.Now().Format(time.RFC3339)
	if _, err := tx.Exec(`
		UPDATE checkout_venta_items
		SET producto_id = ?, producto_nombre = ?, cantidad = ?,
		    precio_unitario_cop = ?, total_cop = ?, notas = ?,
		    estado = 'pendiente', error = '', updated_at = ?
		WHERE id = ? AND checkout_id = ?`,
		productID, productName, quantity, unitPrice, total, strings.TrimSpace(notes), now, itemID, checkoutID); err != nil {
		return err
	}
	if err := touchCheckoutTx(tx, checkoutID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func updateCheckoutChangeItem(db *sql.DB, userID int, itemID int64, quantity int, name, line string) error {
	if quantity <= 0 {
		return checkoutBusinessErrorf("La cantidad debe ser positiva.")
	}
	var textErr error
	name, textErr = checkoutText(name, "El nombre del producto", 180)
	if textErr != nil {
		return textErr
	}
	line, textErr = checkoutText(line, "La línea del producto", 120)
	if textErr != nil {
		return textErr
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
	var checkoutID int64
	var direction, productID string
	var isNew int
	if err := tx.QueryRow(`
		SELECT i.checkout_id, i.direccion, i.producto_id, i.es_nuevo
		FROM checkout_cambio_items i
		JOIN checkout_operaciones c ON c.id = i.checkout_id
		WHERE i.id = ? AND c.user_id = ? AND c.estado IN ('borrador', 'parcial')
		  AND i.estado IN ('pendiente', 'error')`, itemID, userID).Scan(&checkoutID, &direction, &productID, &isNew); err != nil {
		if err == sql.ErrNoRows {
			return checkoutBusinessErrorf("La línea de cambio ya no está disponible para editar.")
		}
		return err
	}
	name = strings.TrimSpace(name)
	line = strings.TrimSpace(line)
	if isNew == 1 {
		if name == "" {
			return checkoutBusinessErrorf("El nombre del producto entrante es obligatorio.")
		}
		if line == "" {
			line = "Sin línea"
		}
	} else {
		var catalogName string
		if err := tx.QueryRow(`SELECT nombre FROM productos WHERE sku = ?`, productID).Scan(&catalogName); err != nil {
			if err == sql.ErrNoRows {
				return checkoutBusinessErrorf("El producto de cambio ya no existe.")
			}
			return err
		}
		if name == "" {
			name = catalogName
		}
		line = ""
	}
	if direction == "salida" {
		var catalogName string
		if err := tx.QueryRow(`SELECT nombre FROM productos WHERE sku = ?`, productID).Scan(&catalogName); err != nil {
			if err == sql.ErrNoRows {
				return checkoutBusinessErrorf("El producto saliente ya no existe.")
			}
			return err
		}
		name = catalogName
		line = ""
	}
	now := time.Now().Format(time.RFC3339)
	if _, err := tx.Exec(`
		UPDATE checkout_cambio_items
		SET producto_nombre = ?, linea = ?, cantidad = ?, estado = 'pendiente', error = '', updated_at = ?
		WHERE id = ? AND checkout_id = ?`, name, line, quantity, now, itemID, checkoutID); err != nil {
		return err
	}
	if err := touchCheckoutTx(tx, checkoutID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func discardCheckoutItem(db *sql.DB, userID int, kind string, itemID int64) error {
	if kind != "venta" && kind != "cambio" {
		return checkoutBusinessErrorf("Tipo de línea inválido.")
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
	table := "checkout_venta_items"
	if kind == "cambio" {
		table = "checkout_cambio_items"
	}
	if !validSQLiteIdentifier(table) {
		return fmt.Errorf("tabla de checkout inválida")
	}
	query := fmt.Sprintf(`
		UPDATE %s
		SET estado = 'descartada', error = '', updated_at = ?
		WHERE id = ? AND estado IN ('pendiente', 'error')
		  AND checkout_id IN (
			SELECT id FROM checkout_operaciones
			WHERE user_id = ? AND estado IN ('borrador', 'parcial')
		)`, table)
	result, err := tx.Exec(query, time.Now().Format(time.RFC3339), itemID, userID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return checkoutBusinessErrorf("La línea ya no está disponible para eliminar.")
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func discardActiveCheckout(db *sql.DB, userID int) error {
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
	checkoutID, err := ensureCheckoutTx(tx, userID)
	if err != nil {
		return err
	}
	now := time.Now().Format(time.RFC3339)
	if _, err := tx.Exec(`
		UPDATE checkout_venta_items SET estado = 'descartada', error = '', updated_at = ?
		WHERE checkout_id = ? AND estado IN ('pendiente', 'error')`, now, checkoutID); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		UPDATE checkout_cambio_items SET estado = 'descartada', error = '', updated_at = ?
		WHERE checkout_id = ? AND estado IN ('pendiente', 'error')`, now, checkoutID); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		UPDATE checkout_operaciones SET estado = 'descartado', updated_at = ?
		WHERE id = ? AND user_id = ? AND estado IN ('borrador', 'parcial')`, now, checkoutID, userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
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
			if wantsJSONRequest(r) {
				writeJSONErrorResponse(w, http.StatusUnauthorized, "La sesión no es válida o ha expirado.")
				return
			}
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

func migrateCambioOperationsSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS cambio_operaciones (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fecha TEXT NOT NULL,
			persona_cambio TEXT NOT NULL DEFAULT '',
			notas TEXT NOT NULL DEFAULT '',
			saliente_producto_id TEXT NOT NULL,
			saliente_producto_nombre TEXT NOT NULL DEFAULT '',
			saliente_cantidad INTEGER NOT NULL CHECK (saliente_cantidad > 0),
			entrante_producto_id TEXT NOT NULL,
			entrante_producto_nombre TEXT NOT NULL DEFAULT '',
			entrante_cantidad INTEGER NOT NULL CHECK (entrante_cantidad > 0),
			usuario TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_cambio_operaciones_fecha ON cambio_operaciones (fecha);
	`)
	return err
}

func migrateCambioItemsSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS cambio_operacion_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			operacion_id INTEGER NOT NULL,
			direccion TEXT NOT NULL CHECK (direccion IN ('salida', 'entrada')),
			producto_id TEXT NOT NULL,
			producto_nombre TEXT NOT NULL DEFAULT '',
			linea TEXT NOT NULL DEFAULT '',
			cantidad INTEGER NOT NULL CHECK (cantidad > 0),
			es_nuevo INTEGER NOT NULL DEFAULT 0 CHECK (es_nuevo IN (0, 1)),
			orden INTEGER NOT NULL,
			FOREIGN KEY (operacion_id) REFERENCES cambio_operaciones(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_cambio_operacion_items_operacion
			ON cambio_operacion_items(operacion_id, orden);
	`)
	return err
}

func migrateCheckoutSchema(tx *sql.Tx) error {
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "tipo", definition: "TEXT NOT NULL DEFAULT 'producto'"},
		{name: "producto_nombre", definition: "TEXT NOT NULL DEFAULT ''"},
		{name: "checkout_id", definition: "INTEGER"},
	} {
		if err := ensureSQLiteColumnTx(tx, "ventas", column.name, column.definition); err != nil {
			return err
		}
	}

	_, err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS checkout_operaciones (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			cliente TEXT NOT NULL DEFAULT '',
			metodo_pago TEXT NOT NULL DEFAULT '',
			notas TEXT NOT NULL DEFAULT '',
			estado TEXT NOT NULL DEFAULT 'borrador'
				CHECK (estado IN ('borrador', 'parcial', 'confirmado', 'descartado')),
			total_cop INTEGER NOT NULL DEFAULT 0 CHECK (total_cop >= 0),
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_checkout_active_user
			ON checkout_operaciones(user_id)
			WHERE estado IN ('borrador', 'parcial');
		CREATE INDEX IF NOT EXISTS idx_checkout_user_updated
			ON checkout_operaciones(user_id, updated_at);

		CREATE TABLE IF NOT EXISTS checkout_venta_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			checkout_id INTEGER NOT NULL,
			tipo TEXT NOT NULL CHECK (tipo IN ('producto', 'cargo')),
			producto_id TEXT NOT NULL DEFAULT '',
			producto_nombre TEXT NOT NULL DEFAULT '',
			cantidad INTEGER NOT NULL CHECK (cantidad > 0),
			precio_unitario_cop INTEGER NOT NULL CHECK (precio_unitario_cop >= 0),
			total_cop INTEGER NOT NULL CHECK (total_cop >= 0),
			notas TEXT NOT NULL DEFAULT '',
			orden INTEGER NOT NULL,
			estado TEXT NOT NULL DEFAULT 'pendiente'
				CHECK (estado IN ('pendiente', 'procesada', 'error', 'descartada')),
			error TEXT NOT NULL DEFAULT '',
			venta_id INTEGER,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY (checkout_id) REFERENCES checkout_operaciones(id) ON DELETE CASCADE,
			FOREIGN KEY (venta_id) REFERENCES ventas(id) ON DELETE SET NULL
		);
		CREATE INDEX IF NOT EXISTS idx_checkout_venta_items_checkout
			ON checkout_venta_items(checkout_id, orden);
		CREATE INDEX IF NOT EXISTS idx_checkout_venta_items_status
			ON checkout_venta_items(checkout_id, estado);

		CREATE TABLE IF NOT EXISTS checkout_cambio_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			checkout_id INTEGER NOT NULL,
			direccion TEXT NOT NULL CHECK (direccion IN ('salida', 'entrada')),
			producto_id TEXT NOT NULL,
			producto_nombre TEXT NOT NULL DEFAULT '',
			linea TEXT NOT NULL DEFAULT '',
			cantidad INTEGER NOT NULL CHECK (cantidad > 0),
			es_nuevo INTEGER NOT NULL DEFAULT 0 CHECK (es_nuevo IN (0, 1)),
			orden INTEGER NOT NULL,
			estado TEXT NOT NULL DEFAULT 'pendiente'
				CHECK (estado IN ('pendiente', 'procesada', 'error', 'descartada')),
			error TEXT NOT NULL DEFAULT '',
			processed_at TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY (checkout_id) REFERENCES checkout_operaciones(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_checkout_cambio_items_checkout
			ON checkout_cambio_items(checkout_id, orden);
		CREATE INDEX IF NOT EXISTS idx_checkout_cambio_items_status
			ON checkout_cambio_items(checkout_id, estado);
		CREATE INDEX IF NOT EXISTS idx_ventas_checkout
			ON ventas(checkout_id);
	`)
	return err
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
	if err := applySchemaMigration(db, 6, migrateCambioOperationsSchema); err != nil {
		return nil, err
	}
	if err := applySchemaMigration(db, 7, migrateCheckoutSchema); err != nil {
		return nil, err
	}
	if err := applySchemaMigration(db, 8, migrateCambioItemsSchema); err != nil {
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
		"checkout_cambio_items",
		"checkout_venta_items",
		"checkout_operaciones",
		"cambios",
		"cambio_operacion_items",
		"cambio_operaciones",
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
		"templates/carrito.html",
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

		dashboardResponse, err := buildDashboardData(db, startStr, endStr, startDate, endDate)
		if err != nil {
			http.Error(w, "Error al consultar ventas", http.StatusInternalServerError)
			return
		}

		data := dashboardData{
			Title:           "Resumen de negocio",
			Subtitle:        "",
			EstadoConteos:   estadoConteos,
			MetodosPago:     dashboardResponse.MetodosPago,
			PieSlices:       dashboardResponse.PieSlices,
			PieTotal:        dashboardResponse.PieTotal,
			MaxTimeline:     dashboardResponse.MaxTimeline,
			MaxTimelineText: dashboardResponse.MaxTimelineText,
			Timeline:        dashboardResponse.Timeline,
			Sales:           dashboardResponse.Sales,
			CurrentUser:     currentUser,
			RangeStart:      startStr,
			RangeEnd:        endStr,
			RangeTotal:      dashboardResponse.RangeTotal,
			RangeCount:      dashboardResponse.RangeCount,
			ChangeCount:     dashboardResponse.ChangeCount,
			Changes:         dashboardResponse.Changes,
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

		data, err := buildDashboardData(db, startStr, endStr, startDate, endDate)
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
				COALESCE(NULLIF(v.producto_nombre, ''), p.nombre, ''),
				v.cantidad,
				v.precio_unitario_cop,
				v.total_cop,
				v.metodo_pago,
				v.notas,
				COALESCE(v.tipo, 'producto')
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

		_ = cw.Write([]string{"venta_id", "fecha", "sku", "producto", "cantidad", "precio_unitario", "total", "metodo_pago", "notas", "tipo"})

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
				tipo       string
			)
			if err := rows.Scan(&id, &fechaRaw, &sku, &nombre, &cantidad, &precioUnit, &total, &metodo, &notas, &tipo); err != nil {
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
				tipo,
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

	isPaymentMethod := func(value string) bool {
		value = strings.TrimSpace(value)
		for _, method := range paymentMethods {
			if value == method {
				return true
			}
		}
		return false
	}
	parseOptionalCOP := func(raw string) (int64, error) {
		if strings.TrimSpace(raw) == "" {
			return 0, nil
		}
		parsed, err := parseCOPInteger(raw)
		if err != nil || parsed <= 0 {
			return 0, checkoutBusinessErrorf("El importe debe ser mayor a cero.")
		}
		return int64(parsed), nil
	}
	parsePositiveQuantity := func(raw string) (int, error) {
		parsed, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || parsed <= 0 {
			return 0, checkoutBusinessErrorf("La cantidad debe ser un número positivo.")
		}
		return parsed, nil
	}
	renderCheckout := func(w http.ResponseWriter, r *http.Request, flash, errorText string) {
		currentUser := userFromContext(r)
		if currentUser == nil {
			http.Error(w, "Sesión requerida.", http.StatusUnauthorized)
			return
		}
		productsSnapshot, err := loadProductos(db)
		if err != nil {
			http.Error(w, "Error al consultar productos.", http.StatusInternalServerError)
			return
		}
		stockByProduct, err := availableCountsByProduct(db)
		if err != nil {
			http.Error(w, "Error al consultar stock.", http.StatusInternalServerError)
			return
		}
		checkout, saleItems, changeItems, err := loadActiveCheckout(db, currentUser.ID)
		if err != nil {
			http.Error(w, "Error al cargar el carrito.", http.StatusInternalServerError)
			return
		}
		data := checkoutPageData{
			Title:          "Carrito",
			Subtitle:       "Agrupa ventas, cargos y cambios antes de confirmar.",
			Flash:          flash,
			Error:          errorText,
			Checkout:       checkout,
			SaleItems:      saleItems,
			ChangeItems:    changeItems,
			Products:       productsSnapshot,
			StockByProduct: stockByProduct,
			PaymentMethods: paymentMethods,
			CurrentUser:    currentUser,
		}
		if err := tmpl.ExecuteTemplate(w, "carrito.html", data); err != nil {
			http.Error(w, "Error al renderizar el carrito.", http.StatusInternalServerError)
		}
	}

	mux.HandleFunc("/carrito", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		renderCheckout(w, r, r.URL.Query().Get("mensaje"), r.URL.Query().Get("error"))
	})

	mux.HandleFunc("/carrito/details", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/carrito", "", "No se pudo leer el formulario.")
			return
		}
		method := strings.TrimSpace(r.FormValue("metodo_pago"))
		if method != "" && !isPaymentMethod(method) {
			redirectWithMessage(w, r, "/carrito", "", "Selecciona un método de pago válido.")
			return
		}
		if err := updateCheckoutDetails(db, currentUser.ID, r.FormValue("cliente"), method, r.FormValue("notas")); err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		redirectWithMessage(w, r, "/carrito", "Datos del checkout actualizados.", "")
	})

	mux.HandleFunc("/carrito/items/venta", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/carrito", "", "No se pudo leer el formulario.")
			return
		}
		quantity, err := parsePositiveQuantity(r.FormValue("cantidad"))
		if err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		price, err := parseOptionalCOP(r.FormValue("precio_unitario"))
		if err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		if _, err := addCheckoutSaleItem(db, currentUser.ID, checkoutSaleInput{
			Tipo:              "producto",
			ProductoID:        r.FormValue("producto_id"),
			Cantidad:          quantity,
			PrecioUnitarioCOP: price,
			Notas:             r.FormValue("notas"),
		}); err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		redirectWithMessage(w, r, "/carrito", "Venta agregada al carrito.", "")
	})

	mux.HandleFunc("/carrito/items/cargo", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/carrito", "", "No se pudo leer el formulario.")
			return
		}
		amount, err := parseOptionalCOP(r.FormValue("monto"))
		if err != nil || amount <= 0 {
			if err == nil {
				err = checkoutBusinessErrorf("El cargo debe tener un valor mayor a cero.")
			}
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		if _, err := addCheckoutSaleItem(db, currentUser.ID, checkoutSaleInput{
			Tipo:     "cargo",
			TotalCOP: amount,
			Notas:    r.FormValue("notas"),
		}); err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		redirectWithMessage(w, r, "/carrito", "Cargo agregado al carrito.", "")
	})

	mux.HandleFunc("/carrito/items/cambio", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/carrito", "", "No se pudo leer el formulario.")
			return
		}
		quantity, err := parsePositiveQuantity(r.FormValue("cantidad"))
		if err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		direction := strings.TrimSpace(r.FormValue("direccion"))
		input := checkoutChangeInput{Direccion: direction, Cantidad: quantity}
		if direction == "salida" {
			input.ProductoID = r.FormValue("producto_id")
		} else if direction == "entrada" {
			mode := r.FormValue("incoming_mode")
			if mode == "new" {
				input.EsNuevo = true
				input.ProductoID = r.FormValue("incoming_new_sku")
				input.ProductoNombre = r.FormValue("incoming_new_name")
				input.Linea = r.FormValue("incoming_new_line")
			} else {
				input.ProductoID = r.FormValue("incoming_existing_id")
			}
		} else {
			redirectWithMessage(w, r, "/carrito", "", "Selecciona una dirección de cambio válida.")
			return
		}
		if _, err := addCheckoutChangeItem(db, currentUser.ID, input); err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		redirectWithMessage(w, r, "/carrito", "Línea de cambio agregada al carrito.", "")
	})

	mux.HandleFunc("/carrito/items/cambio-pair", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/carrito", "", "No se pudo leer el formulario.")
			return
		}

		outgoingQuantity, err := parsePositiveQuantity(r.FormValue("salida_cantidad"))
		if err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		incomingQuantity, err := parsePositiveQuantity(r.FormValue("entrada_cantidad"))
		if err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}

		outgoing := checkoutChangeInput{
			Direccion:  "salida",
			ProductoID: r.FormValue("salida_producto_id"),
			Cantidad:   outgoingQuantity,
		}
		incoming := checkoutChangeInput{
			Direccion: "entrada",
			Cantidad:  incomingQuantity,
		}

		switch strings.TrimSpace(r.FormValue("incoming_mode")) {
		case "existing":
			incoming.ProductoID = r.FormValue("incoming_existing_id")
		case "new":
			incoming.EsNuevo = true
			incoming.ProductoID = r.FormValue("incoming_new_sku")
			incoming.ProductoNombre = r.FormValue("incoming_new_name")
			incoming.Linea = r.FormValue("incoming_new_line")
		default:
			redirectWithMessage(w, r, "/carrito", "", "Selecciona el tipo de producto entrante.")
			return
		}

		if err := addCheckoutChangePair(db, currentUser.ID, outgoing, incoming); err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		redirectWithMessage(w, r, "/carrito", "Cambio agregado al carrito.", "")
	})

	mux.HandleFunc("/carrito/item/update", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/carrito", "", "No se pudo leer el formulario.")
			return
		}
		itemID, err := strconv.ParseInt(r.FormValue("item_id"), 10, 64)
		if err != nil || itemID <= 0 {
			redirectWithMessage(w, r, "/carrito", "", "Línea inválida.")
			return
		}
		switch r.FormValue("tipo") {
		case "venta":
			quantity, quantityErr := parsePositiveQuantity(r.FormValue("cantidad"))
			price, priceErr := parseOptionalCOP(r.FormValue("precio_unitario"))
			if price == 0 {
				price, priceErr = parseOptionalCOP(r.FormValue("monto"))
			}
			if quantityErr != nil || priceErr != nil || price <= 0 {
				if quantityErr != nil {
					err = quantityErr
				} else if priceErr != nil {
					err = priceErr
				} else {
					err = checkoutBusinessErrorf("El importe debe ser mayor a cero.")
				}
				redirectWithMessage(w, r, "/carrito", "", err.Error())
				return
			}
			err = updateCheckoutSaleItem(db, currentUser.ID, itemID, quantity, price, r.FormValue("notas"))
		case "cambio":
			quantity, quantityErr := parsePositiveQuantity(r.FormValue("cantidad"))
			if quantityErr != nil {
				redirectWithMessage(w, r, "/carrito", "", quantityErr.Error())
				return
			}
			err = updateCheckoutChangeItem(db, currentUser.ID, itemID, quantity, r.FormValue("producto_nombre"), r.FormValue("linea"))
		default:
			err = checkoutBusinessErrorf("Tipo de línea inválido.")
		}
		if err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		redirectWithMessage(w, r, "/carrito", "Línea actualizada.", "")
	})

	mux.HandleFunc("/carrito/item/delete", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		itemID, err := strconv.ParseInt(r.FormValue("item_id"), 10, 64)
		if err != nil || itemID <= 0 {
			redirectWithMessage(w, r, "/carrito", "", "Línea inválida.")
			return
		}
		if err := discardCheckoutItem(db, currentUser.ID, r.FormValue("tipo"), itemID); err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		redirectWithMessage(w, r, "/carrito", "Línea eliminada del checkout.", "")
	})

	mux.HandleFunc("/carrito/descartar", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		if err := discardActiveCheckout(db, currentUser.ID); err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		redirectWithMessage(w, r, "/carrito", "Checkout descartado.", "")
	})

	mux.HandleFunc("/checkout", func(w http.ResponseWriter, r *http.Request) {
		currentUser := userFromContext(r)
		if r.Method != http.MethodPost || currentUser == nil {
			http.Error(w, "Método no permitido.", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			redirectWithMessage(w, r, "/carrito", "", "No se pudo leer el formulario.")
			return
		}
		method := strings.TrimSpace(r.FormValue("metodo_pago"))
		if !isPaymentMethod(method) {
			redirectWithMessage(w, r, "/carrito", "", "Selecciona un método de pago válido.")
			return
		}
		checkout, _, _, err := loadActiveCheckout(db, currentUser.ID)
		if err != nil {
			redirectWithMessage(w, r, "/carrito", "", "No se pudo cargar el checkout.")
			return
		}
		result, err := processCheckout(db, currentUser.ID, checkout.ID, r.FormValue("cliente"), method, r.FormValue("notas"), currentUser)
		if err != nil {
			redirectWithMessage(w, r, "/carrito", "", err.Error())
			return
		}
		if result.State == checkoutStatePartial {
			errorText := "Hay líneas pendientes para corregir o reintentar."
			if len(result.Errors) > 0 {
				errorText = result.Errors[0]
			}
			redirectWithMessage(w, r, "/carrito", "Checkout parcial: se procesaron las líneas disponibles.", errorText)
			return
		}
		redirectWithMessage(w, r, "/carrito", "Checkout confirmado correctamente.", "")
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
		_, ok := findProduct(productsSnapshot, productID)
		if !ok {
			productID = productsSnapshot[0].ID
		}

		data := cambioFormData{
			Title:       "Registrar cambio",
			Productos:   productsSnapshot,
			Multi:       true,
			OutLines:    []cambioLineDraft{{N: 1, ProductoID: productID, Cantidad: 1}},
			InLines:     []cambioLineDraft{{N: 1, IncomingMode: "existing", IncomingExistingID: productsSnapshot[0].ID, Cantidad: 1}},
			Errors:      map[string]string{},
			CurrentUser: currentUser,
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
		logCambioError := func(stage, productID, incomingMode string, outgoingCount int, cause error) {
			userID := 0
			if currentUser != nil {
				userID = currentUser.ID
			}
			log.Printf("cambio request_id=%s stage=%s user_id=%d product_id=%q incoming_mode=%q outgoing_count=%d error=%v", requestIDFromRequest(r), stage, userID, productID, incomingMode, outgoingCount, cause)
		}

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
			logCambioError("load_products", "", "", 0, err)
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

		if strings.TrimSpace(r.FormValue("multi")) == "1" {
			personaCambio := strings.TrimSpace(r.FormValue("persona_del_cambio"))
			notas := strings.TrimSpace(r.FormValue("notas"))
			errors := make(map[string]string)
			if personaCambio == "" {
				errors["persona_del_cambio"] = "Ingresa la persona responsable del cambio."
			} else if len(personaCambio) > maxCambioPersonBytes {
				errors["persona_del_cambio"] = "La persona responsable supera el máximo permitido."
			}
			if len(notas) > maxCambioNotesBytes {
				errors["notas"] = "Las notas superan el máximo permitido."
			}

			outProductIDs := r.Form["out_product"]
			outQtyValues := r.Form["out_qty"]
			outDrafts := make([]cambioLineDraft, 0, len(outProductIDs))
			outSeen := make(map[string]struct{}, len(outProductIDs))
			for i := 0; i < len(outProductIDs); i++ {
				draft := cambioLineDraft{N: i + 1, ProductoID: strings.TrimSpace(outProductIDs[i])}
				if i < len(outQtyValues) {
					if parsed, err := strconv.Atoi(strings.TrimSpace(outQtyValues[i])); err == nil {
						draft.Cantidad = parsed
					}
				}
				if draft.ProductoID == "" {
					draft.ErrorProducto = "Selecciona un producto."
				} else if _, exists := findProduct(productsSnapshot, draft.ProductoID); !exists {
					draft.ErrorProducto = "El producto no es válido."
				}
				if draft.Cantidad <= 0 {
					draft.ErrorCantidad = "Ingresa una cantidad válida."
				} else if draft.Cantidad > maxCambioQuantity {
					draft.ErrorCantidad = "La cantidad no puede superar 10.000 unidades."
				}
				if draft.ErrorProducto == "" && draft.ErrorCantidad == "" {
					if _, dup := outSeen[draft.ProductoID]; dup {
						draft.ErrorProducto = "El producto ya está en la lista de salidas."
					} else {
						outSeen[draft.ProductoID] = struct{}{}
					}
				}
				outDrafts = append(outDrafts, draft)
			}
			if len(outDrafts) == 0 {
				errors["salientes"] = "Agrega al menos un producto de salida."
			}

			inModes := r.Form["in_mode"]
			inExisting := r.Form["in_existing"]
			inNewSKU := r.Form["in_new_sku"]
			inNewName := r.Form["in_new_name"]
			inNewLine := r.Form["in_new_line"]
			inQtyValues := r.Form["in_qty"]
			inDrafts := make([]cambioLineDraft, 0, len(inModes))
			inSeen := make(map[string]struct{}, len(inModes))
			existingIdx := 0
			newIdx := 0
			for i := 0; i < len(inModes); i++ {
				draft := cambioLineDraft{N: i + 1, IncomingMode: strings.TrimSpace(inModes[i])}
				if i < len(inQtyValues) {
					if parsed, err := strconv.Atoi(strings.TrimSpace(inQtyValues[i])); err == nil {
						draft.Cantidad = parsed
					}
				}
				if draft.IncomingMode == "existing" {
					if existingIdx < len(inExisting) {
						draft.IncomingExistingID = strings.TrimSpace(inExisting[existingIdx])
					}
					existingIdx++
					draft.ProductoID = draft.IncomingExistingID
					if draft.ProductoID == "" {
						draft.ErrorSKU = "Selecciona el producto entrante."
					} else if _, exists := findProduct(productsSnapshot, draft.ProductoID); !exists {
						draft.ErrorSKU = "El producto entrante no es válido."
					}
				} else if draft.IncomingMode == "new" {
					draft.EsNuevo = true
					if newIdx < len(inNewSKU) {
						draft.IncomingNewSKU = strings.TrimSpace(inNewSKU[newIdx])
					}
					if newIdx < len(inNewName) {
						draft.IncomingNewName = strings.TrimSpace(inNewName[newIdx])
					}
					if newIdx < len(inNewLine) {
						draft.IncomingNewLine = strings.TrimSpace(inNewLine[newIdx])
					}
					newIdx++
					draft.ProductoID = draft.IncomingNewSKU
					if draft.ProductoID == "" {
						draft.ErrorSKU = "Ingresa el SKU del producto nuevo."
					} else if _, exists := findProduct(productsSnapshot, draft.ProductoID); exists {
						draft.ErrorSKU = "El SKU ya existe; selecciona el producto existente."
					} else if len(draft.ProductoID) > maxCambioSKUBytes {
						draft.ErrorSKU = "El SKU supera el máximo permitido."
					}
					if draft.IncomingNewName == "" {
						draft.ErrorNombre = "Ingresa el nombre del producto nuevo."
					} else if len(draft.IncomingNewName) > maxCambioNameBytes {
						draft.ErrorNombre = "El nombre supera el máximo permitido."
					}
					if len(draft.IncomingNewLine) > maxCambioLineBytes {
						draft.ErrorLinea = "La línea supera el máximo permitido."
					}
				} else {
					draft.ErrorSKU = "Selecciona el tipo de entrada."
				}
				if draft.Cantidad <= 0 {
					draft.ErrorCantidad = "Ingresa una cantidad válida."
				} else if draft.Cantidad > maxCambioQuantity {
					draft.ErrorCantidad = "La cantidad no puede superar 10.000 unidades."
				}
				if draft.ErrorSKU == "" && draft.ErrorCantidad == "" {
					if _, dup := inSeen[draft.ProductoID]; dup {
						draft.ErrorSKU = "El producto ya está en la lista de entradas."
					} else {
						inSeen[draft.ProductoID] = struct{}{}
					}
				}
				inDrafts = append(inDrafts, draft)
			}
			if len(inDrafts) == 0 {
				errors["entrantes"] = "Agrega al menos un producto de entrada."
			}

			renderCambioMultiForm := func(status int) {
				data := cambioFormData{
					Title:         "Registrar cambio",
					Productos:     productsSnapshot,
					PersonaCambio: personaCambio,
					Notas:         notas,
					Multi:         true,
					OutLines:      outDrafts,
					InLines:       inDrafts,
					Errors:        errors,
					CurrentUser:   currentUser,
				}
				w.WriteHeader(status)
				if err := tmpl.ExecuteTemplate(w, "cambio_new.html", data); err != nil {
					logCambioError("render_multi_form", "", "", len(outDrafts), err)
				}
			}

			hasFieldErrors := false
			for _, d := range outDrafts {
				if d.ErrorProducto != "" || d.ErrorCantidad != "" {
					hasFieldErrors = true
				}
			}
			for _, d := range inDrafts {
				if d.ErrorSKU != "" || d.ErrorNombre != "" || d.ErrorLinea != "" || d.ErrorCantidad != "" {
					hasFieldErrors = true
				}
			}

			if len(errors) > 0 || hasFieldErrors {
				if wantsJSON {
					message := "Datos inválidos."
					for _, key := range []string{"persona_del_cambio", "salientes", "entrantes", "notas"} {
						if msg, ok := errors[key]; ok && msg != "" {
							message = msg
							break
						}
					}
					writeJSONError(http.StatusBadRequest, message, errors)
					return
				}
				renderCambioMultiForm(http.StatusBadRequest)
				return
			}

			salientes := make([]cambioLineInput, 0, len(outDrafts))
			for _, d := range outDrafts {
				salientes = append(salientes, cambioLineInput{ProductoID: d.ProductoID, Cantidad: d.Cantidad})
			}
			entrantes := make([]cambioLineInput, 0, len(inDrafts))
			for _, d := range inDrafts {
				entrantes = append(entrantes, cambioLineInput{
					ProductoID: d.ProductoID,
					Cantidad:   d.Cantidad,
					EsNuevo:    d.EsNuevo,
					Nombre:     d.IncomingNewName,
					Linea:      d.IncomingNewLine,
				})
			}

			tx, err := db.Begin()
			if err != nil {
				logCambioError("begin_multi_transaction", "", "", len(outDrafts), err)
				if wantsJSON {
					writeJSONError(http.StatusInternalServerError, "Error al iniciar el cambio.", nil)
					return
				}
				http.Error(w, "Error al iniciar el cambio", http.StatusInternalServerError)
				return
			}
			now := time.Now().Format(time.RFC3339)
			notaMovimiento := strings.TrimSpace(fmt.Sprintf("%s %s", personaCambio, notas))
			result, err := applyCambioInventoryMulti(tx, cambioMultiInput{
				Salientes:     salientes,
				Entrantes:     entrantes,
				PersonaCambio: personaCambio,
				Notas:         notas,
				MovementNote:  notaMovimiento,
				User:          currentUser,
				Now:           now,
			})
			if err != nil {
				logCambioError("apply_multi_inventory", "", "", len(outDrafts), err)
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					log.Printf("rollback cambio multi: %v", rollbackErr)
				}
				if err == errCambioIncomingSKUExists {
					errors["entrantes"] = "El SKU de un producto entrante ya existe; selecciona el producto existente."
					if wantsJSON {
						writeJSONError(http.StatusBadRequest, errors["entrantes"], errors)
						return
					}
					renderCambioMultiForm(http.StatusBadRequest)
					return
				}
				if strings.HasPrefix(err.Error(), "stock insuficiente para") {
					errors["salientes"] = err.Error()
					if wantsJSON {
						writeJSONError(http.StatusBadRequest, err.Error(), errors)
						return
					}
					renderCambioMultiForm(http.StatusBadRequest)
					return
				}
				if wantsJSON {
					writeJSONError(http.StatusInternalServerError, "No se pudo actualizar el inventario del cambio.", nil)
					return
				}
				http.Error(w, "No se pudo actualizar el inventario del cambio", http.StatusInternalServerError)
				return
			}
			if err := tx.Commit(); err != nil {
				logCambioError("commit_multi_transaction", "", "", len(outDrafts), err)
				if wantsJSON {
					writeJSONError(http.StatusInternalServerError, "Error al confirmar el cambio.", nil)
					return
				}
				http.Error(w, "Error al confirmar el cambio", http.StatusInternalServerError)
				return
			}

			confirmOut := make([]cambioConfirmLine, 0, len(outDrafts))
			for _, d := range outDrafts {
				name := d.ProductoID
				if p, exists := findProduct(productsSnapshot, d.ProductoID); exists {
					name = p.Name
				}
				confirmOut = append(confirmOut, cambioConfirmLine{ProductoID: d.ProductoID, ProductoNombre: name, Cantidad: d.Cantidad})
			}
			confirmIn := make([]cambioConfirmLine, 0, len(inDrafts))
			for _, d := range inDrafts {
				name := d.IncomingNewName
				if !d.EsNuevo {
					name = d.ProductoID
					if p, exists := findProduct(productsSnapshot, d.ProductoID); exists {
						name = p.Name
					}
				}
				confirmIn = append(confirmIn, cambioConfirmLine{ProductoID: d.ProductoID, ProductoNombre: name, Cantidad: d.Cantidad, EsNuevo: d.EsNuevo})
			}

			if wantsJSON {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok":        true,
					"salientes": len(result.SalienteUnitIDs),
					"entrantes": len(result.EntranteUnitIDs),
					"mensaje":   "Cambio registrado correctamente.",
				})
				return
			}

			confirmData := cambioConfirmData{
				Title:         "Cambio registrado",
				PersonaCambio: personaCambio,
				Notas:         notas,
				SalienteLines: confirmOut,
				EntranteLines: confirmIn,
				CurrentUser:   currentUser,
			}
			if err := tmpl.ExecuteTemplate(w, "cambio_confirm.html", confirmData); err != nil {
				http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
			}
			return
		}

		productID := strings.TrimSpace(r.FormValue("producto_id"))
		personaCambio := strings.TrimSpace(r.FormValue("persona_del_cambio"))
		notas := strings.TrimSpace(r.FormValue("notas"))
		rawSalientes := r.Form["salientes"]
		salientes := make([]string, 0, len(rawSalientes))
		seenSalientes := make(map[string]struct{}, len(rawSalientes))
		duplicateSaliente := false
		for _, rawUnitID := range rawSalientes {
			unitID := strings.TrimSpace(rawUnitID)
			if unitID == "" {
				continue
			}
			if _, exists := seenSalientes[unitID]; exists {
				duplicateSaliente = true
				continue
			}
			seenSalientes[unitID] = struct{}{}
			salientes = append(salientes, unitID)
		}
		incomingMode := strings.TrimSpace(r.FormValue("incoming_mode"))
		incomingExistingID := strings.TrimSpace(r.FormValue("incoming_existing_id"))
		incomingExistingQtyValue := strings.TrimSpace(r.FormValue("incoming_existing_qty"))
		incomingNewSKU := strings.TrimSpace(r.FormValue("incoming_new_sku"))
		incomingNewName := strings.TrimSpace(r.FormValue("incoming_new_name"))
		incomingNewLine := strings.TrimSpace(r.FormValue("incoming_new_line"))
		incomingNewQtyValue := strings.TrimSpace(r.FormValue("incoming_new_qty"))

		errors := make(map[string]string)

		selectedProduct, ok := findProduct(productsSnapshot, productID)
		if !ok {
			errors["producto_id"] = "Selecciona un producto válido."
			selectedProduct = productsSnapshot[0]
			productID = selectedProduct.ID
		}

		if personaCambio == "" {
			errors["persona_del_cambio"] = "Ingresa la persona responsable del cambio."
		} else if len(personaCambio) > maxCambioPersonBytes {
			errors["persona_del_cambio"] = "La persona responsable supera el máximo permitido."
		}
		if len(notas) > maxCambioNotesBytes {
			errors["notas"] = "Las notas superan el máximo permitido."
		}

		availableUnits, err := availableUnitsByProduct(db, productID)
		if err != nil {
			logCambioError("load_available_units", productID, incomingMode, len(salientes), err)
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
		if duplicateSaliente && errors["salientes"] == "" {
			errors["salientes"] = "No selecciones la misma unidad más de una vez."
		}
		if len(validSalientes) > maxCambioQuantity {
			errors["salientes"] = "La cantidad saliente no puede superar 10.000 unidades."
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
			} else if incomingExistingQty > maxCambioQuantity {
				errors["incoming_existing_qty"] = "La cantidad no puede superar 10.000 unidades."
			}
		} else if incomingMode == "new" {
			if incomingNewSKU == "" {
				errors["incoming_new_sku"] = "Ingresa el SKU del producto nuevo."
			} else if _, exists := findProduct(productsSnapshot, incomingNewSKU); exists {
				errors["incoming_new_sku"] = "El SKU ya existe; selecciona el producto existente."
			} else if len(incomingNewSKU) > maxCambioSKUBytes {
				errors["incoming_new_sku"] = "El SKU supera el máximo permitido."
			}
			if incomingNewName == "" {
				errors["incoming_new_name"] = "Ingresa el nombre del producto nuevo."
			} else if len(incomingNewName) > maxCambioNameBytes {
				errors["incoming_new_name"] = "El nombre supera el máximo permitido."
			}
			if len(incomingNewLine) > maxCambioLineBytes {
				errors["incoming_new_line"] = "La línea supera el máximo permitido."
			}
			if incomingNewQty <= 0 {
				errors["incoming_new_qty"] = "Ingresa una cantidad válida para la entrada."
			} else if incomingNewQty > maxCambioQuantity {
				errors["incoming_new_qty"] = "La cantidad no puede superar 10.000 unidades."
			}
		}

		if len(errors) > 0 {
			if wantsJSON {
				message := "Datos inválidos."
				for _, key := range []string{"producto_id", "persona_del_cambio", "salientes", "incoming_mode", "incoming_existing_id", "incoming_existing_qty", "incoming_new_sku", "incoming_new_name", "incoming_new_line", "incoming_new_qty", "notas"} {
					if msg, ok := errors[key]; ok && msg != "" {
						message = msg
						break
					}
				}
				writeJSONError(http.StatusBadRequest, message, errors)
				return
			}
			redirectWithMessage(w, r, "/cambio/new", "", "Revisa los datos del cambio.")
			return
		}

		tx, err := db.Begin()
		if err != nil {
			logCambioError("begin_transaction", productID, incomingMode, len(salientes), err)
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al iniciar el cambio.", nil)
				return
			}
			http.Error(w, "Error al iniciar el cambio", http.StatusInternalServerError)
			return
		}

		now := time.Now().Format(time.RFC3339)
		notaMovimiento := strings.TrimSpace(fmt.Sprintf("%s %s", personaCambio, notas))
		incomingProductID := incomingExistingID
		incomingQuantity := incomingExistingQty
		incomingNew := false
		if incomingMode == "new" {
			incomingProductID = incomingNewSKU
			incomingQuantity = incomingNewQty
			incomingNew = true
		}
		incomingProductName := incomingNewName
		if !incomingNew {
			if incomingProduct, exists := findProduct(productsSnapshot, incomingProductID); exists {
				incomingProductName = incomingProduct.Name
			}
		}
		result, err := applyCambioInventory(tx, cambioInventoryInput{
			ProductID:         productID,
			OutgoingName:      selectedProduct.Name,
			OutgoingUnitIDs:   salientes,
			IncomingProductID: incomingProductID,
			IncomingNew:       incomingNew,
			IncomingName:      incomingProductName,
			IncomingLine:      incomingNewLine,
			IncomingQuantity:  incomingQuantity,
			PersonaCambio:     personaCambio,
			Notas:             notas,
			MovementNote:      notaMovimiento,
			User:              currentUser,
			Now:               now,
		})
		if err != nil {
			logCambioError("apply_inventory", productID, incomingMode, len(salientes), err)
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
				redirectWithMessage(w, r, "/cambio/new", "", "No hay stock disponible suficiente para completar el cambio.")
				return
			}
			if err == errCambioIncomingSKUExists {
				errors["incoming_new_sku"] = "El SKU ya fue registrado; selecciona el producto existente."
				if wantsJSON {
					writeJSONError(http.StatusBadRequest, errors["incoming_new_sku"], errors)
					return
				}
				redirectWithMessage(w, r, "/cambio/new", "", "El SKU del producto entrante ya existe; selecciona el producto existente.")
				return
			}
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "No se pudo actualizar el inventario del cambio.", nil)
				return
			}
			http.Error(w, "No se pudo actualizar el inventario del cambio", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			logCambioError("commit_transaction", productID, incomingMode, len(salientes), err)
			if wantsJSON {
				writeJSONError(http.StatusInternalServerError, "Error al confirmar el cambio.", nil)
				return
			}
			http.Error(w, "Error al confirmar el cambio", http.StatusInternalServerError)
			return
		}
		salientesMarcadas := result.OutgoingUnitIDs
		entrantes := result.IncomingUnitIDs
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
			SalienteLines:       []cambioConfirmLine{{ProductoID: productID, ProductoNombre: selectedProduct.Name, Cantidad: len(salientesMarcadas)}},
			EntranteLines:       []cambioConfirmLine{{ProductoID: incomingProductID, ProductoNombre: incomingProductName, Cantidad: len(entrantes), EsNuevo: incomingNew}},
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
