package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE unidades (
			id TEXT PRIMARY KEY,
			producto_id TEXT NOT NULL,
			estado TEXT NOT NULL,
			creado_en TEXT NOT NULL
		);`)
	if err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return db
}

func setupCambioInventoryDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("SEED_DEMO", "")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")
	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedCambioProduct(t *testing.T, db *sql.DB, sku string, quantity int) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO productos (sku, id, linea, nombre)
		VALUES (?, ?, 'Cambios', ?)
	`, sku, sku, "Producto "+sku); err != nil {
		t.Fatalf("insert cambio product %s: %v", sku, err)
	}
	for i := 1; i <= quantity; i++ {
		unitID := fmt.Sprintf("U-%s-%02d", sku, i)
		if _, err := db.Exec(`
			INSERT INTO unidades (id, producto_id, estado, creado_en)
			VALUES (?, ?, 'Disponible', ?)
		`, unitID, sku, time.Date(2026, time.August, i, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)); err != nil {
			t.Fatalf("insert cambio unit %s: %v", unitID, err)
		}
	}
}

func availableCambioCount(t *testing.T, db *sql.DB, sku string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM unidades
		WHERE producto_id = ? AND estado IN ('Disponible', 'available')
	`, sku).Scan(&count); err != nil {
		t.Fatalf("count available units for %s: %v", sku, err)
	}
	return count
}

func totalCambioCount(t *testing.T, db *sql.DB, sku string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM unidades WHERE producto_id = ?`, sku).Scan(&count); err != nil {
		t.Fatalf("count units for %s: %v", sku, err)
	}
	return count
}

func movementCambioCount(t *testing.T, db *sql.DB, movementType, sku string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM movimientos WHERE tipo = ? AND producto_id = ?`, movementType, sku).Scan(&count); err != nil {
		t.Fatalf("count movements %s/%s: %v", movementType, sku, err)
	}
	return count
}

func TestCountInventoryUnitsIncludesReservedUnits(t *testing.T) {
	counts := countInventoryUnits([]inventoryUnit{
		{EstadoClass: "available"},
		{EstadoClass: "reserved"},
		{EstadoClass: "reserved"},
		{EstadoClass: "sold"},
	})

	if counts.available != 1 {
		t.Fatalf("expected one available unit, got %d", counts.available)
	}
	if counts.reserved != 2 {
		t.Fatalf("expected two reserved units, got %d", counts.reserved)
	}
}

func TestSelectAndMarkUnitsSoldFIFO(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	created := []string{
		time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
		time.Date(2024, 1, 2, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
		time.Date(2024, 1, 3, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
	_, err := db.Exec(`INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES
		('U-001', 'P-001', 'Disponible', ?),
		('U-002', 'P-001', 'Disponible', ?),
		('U-003', 'P-001', 'Vendida', ?)
	`, created[0], created[1], created[2])
	if err != nil {
		t.Fatalf("insert unidades: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	ids, err := selectAndMarkUnitsSold(tx, "P-001", 2)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("selectAndMarkUnitsSold: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if len(ids) != 2 || ids[0] != "U-001" || ids[1] != "U-002" {
		t.Fatalf("fifo ids inesperados: %v", ids)
	}

	rows, err := db.Query(`SELECT id, estado FROM unidades WHERE producto_id = 'P-001' ORDER BY id`)
	if err != nil {
		t.Fatalf("query unidades: %v", err)
	}
	defer rows.Close()

	estados := map[string]string{}
	for rows.Next() {
		var id, estado string
		if err := rows.Scan(&id, &estado); err != nil {
			t.Fatalf("scan unidad: %v", err)
		}
		estados[id] = estado
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}

	if estados["U-001"] != "Vendida" || estados["U-002"] != "Vendida" || estados["U-003"] != "Vendida" {
		t.Fatalf("estados inesperados: %v", estados)
	}
}

func TestSelectAndMarkUnitsSoldInsufficient(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	created := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339)
	_, err := db.Exec(`INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES
		('U-010', 'P-002', 'Disponible', ?)
	`, created)
	if err != nil {
		t.Fatalf("insert unidades: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	_, err = selectAndMarkUnitsSold(tx, "P-002", 2)
	if err == nil {
		_ = tx.Rollback()
		t.Fatalf("expected error")
	}
	_ = tx.Rollback()
	if err != errInsufficientStock {
		t.Fatalf("expected errInsufficientStock, got %v", err)
	}
}

func TestDeleteSpecificAvailableUnitsPreservesSelection(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	created := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339)
	_, err := db.Exec(`INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES
		('U-020', 'P-003', 'Disponible', ?),
		('U-021', 'P-003', 'Disponible', ?),
		('U-022', 'P-003', 'Disponible', ?)
	`, created, created, created)
	if err != nil {
		t.Fatalf("insert unidades: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	ids, err := deleteSpecificAvailableUnits(tx, "P-003", []string{"U-022", "U-020"})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("deleteSpecificAvailableUnits: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(ids) != 2 || ids[0] != "U-022" || ids[1] != "U-020" {
		t.Fatalf("selected ids changed order: %v", ids)
	}

	var selected, available int
	if err := db.QueryRow(`SELECT COUNT(*) FROM unidades WHERE producto_id = 'P-003' AND id IN ('U-022', 'U-020')`).Scan(&selected); err != nil {
		t.Fatalf("count deleted: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM unidades WHERE producto_id = 'P-003' AND estado = 'Disponible'`).Scan(&available); err != nil {
		t.Fatalf("count available: %v", err)
	}
	if selected != 0 || available != 1 {
		t.Fatalf("unexpected units deleted=%d available=%d", selected, available)
	}
}

func TestApplyCambioInventoryUpdatesOutgoingAndIncomingCounts(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-CAMBIO-A", 5)
	seedCambioProduct(t, db, "P-CAMBIO-B", 4)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin cambio: %v", err)
	}
	result, err := applyCambioInventory(tx, cambioInventoryInput{
		ProductID:         "P-CAMBIO-A",
		OutgoingUnitIDs:   []string{"U-P-CAMBIO-A-01", "U-P-CAMBIO-A-02"},
		IncomingProductID: "P-CAMBIO-B",
		IncomingQuantity:  3,
		PersonaCambio:     "Cliente test",
		Notas:             "Producto incorrecto",
		MovementNote:      "cliente de prueba",
		User:              &User{Username: "tester", Role: "admin"},
		Now:               "2026-08-07T12:00:00Z",
	})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("applyCambioInventory: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit cambio: %v", err)
	}

	if len(result.OutgoingUnitIDs) != 2 || len(result.IncomingUnitIDs) != 3 {
		t.Fatalf("unexpected cambio result: %+v", result)
	}
	if availableCambioCount(t, db, "P-CAMBIO-A") != 3 || totalCambioCount(t, db, "P-CAMBIO-A") != 3 {
		t.Fatalf("outgoing product quantity was not reduced")
	}
	if availableCambioCount(t, db, "P-CAMBIO-B") != 7 || totalCambioCount(t, db, "P-CAMBIO-B") != 7 {
		t.Fatalf("incoming product quantity was not increased")
	}
	if movementCambioCount(t, db, "cambio_salida", "P-CAMBIO-A") != 2 {
		t.Fatalf("expected two outgoing movements")
	}
	if movementCambioCount(t, db, "cambio_entrada", "P-CAMBIO-B") != 3 {
		t.Fatalf("expected three incoming movements")
	}
	var persona, notes, outgoingName, incomingName string
	var outgoingQuantity, incomingQuantity int
	if err := db.QueryRow(`
		SELECT persona_cambio, notas, saliente_producto_nombre, saliente_cantidad,
		       entrante_producto_nombre, entrante_cantidad
		FROM cambio_operaciones
		WHERE saliente_producto_id = 'P-CAMBIO-A'
	`).Scan(&persona, &notes, &outgoingName, &outgoingQuantity, &incomingName, &incomingQuantity); err != nil {
		t.Fatalf("query structured cambio: %v", err)
	}
	if persona != "Cliente test" || notes != "Producto incorrecto" || outgoingName != "Producto P-CAMBIO-A" || outgoingQuantity != 2 || incomingName != "Producto P-CAMBIO-B" || incomingQuantity != 3 {
		t.Fatalf("unexpected structured cambio: persona=%q notes=%q outgoing=%q/%d incoming=%q/%d", persona, notes, outgoingName, outgoingQuantity, incomingName, incomingQuantity)
	}
}

func TestApplyCambioInventoryCreatesNewIncomingProduct(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-CAMBIO-OUT", 2)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin cambio: %v", err)
	}
	_, err = applyCambioInventory(tx, cambioInventoryInput{
		ProductID:         "P-CAMBIO-OUT",
		OutgoingUnitIDs:   []string{"U-P-CAMBIO-OUT-01"},
		IncomingProductID: "P-CAMBIO-NEW",
		IncomingNew:       true,
		IncomingName:      "Producto recibido",
		IncomingLine:      "Cambios",
		IncomingQuantity:  2,
		MovementNote:      "producto nuevo",
		Now:               "2026-08-07T12:00:00Z",
	})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("applyCambioInventory new product: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit cambio new product: %v", err)
	}

	var productCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = 'P-CAMBIO-NEW'`).Scan(&productCount); err != nil {
		t.Fatalf("count new product: %v", err)
	}
	if productCount != 1 || availableCambioCount(t, db, "P-CAMBIO-NEW") != 2 {
		t.Fatalf("new incoming product was not created with its units")
	}
	if availableCambioCount(t, db, "P-CAMBIO-OUT") != 1 {
		t.Fatalf("outgoing product quantity was not reduced")
	}
}

func TestApplyCambioInventorySameProductUsesNetQuantity(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-CAMBIO-NET", 4)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin cambio: %v", err)
	}
	_, err = applyCambioInventory(tx, cambioInventoryInput{
		ProductID:         "P-CAMBIO-NET",
		OutgoingUnitIDs:   []string{"U-P-CAMBIO-NET-01", "U-P-CAMBIO-NET-02"},
		IncomingProductID: "P-CAMBIO-NET",
		IncomingQuantity:  1,
		MovementNote:      "mismo producto",
		Now:               "2026-08-07T12:00:00Z",
	})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("applyCambioInventory same product: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit same product cambio: %v", err)
	}
	if availableCambioCount(t, db, "P-CAMBIO-NET") != 3 || totalCambioCount(t, db, "P-CAMBIO-NET") != 3 {
		t.Fatalf("same-product cambio did not apply net quantity")
	}
}

func TestApplyCambioInventoryRollsBackOutgoingWhenIncomingFails(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-CAMBIO-ROLLBACK", 2)
	if _, err := db.Exec(`
		CREATE TRIGGER fail_cambio_incoming
		BEFORE INSERT ON unidades
		WHEN NEW.producto_id = 'P-CAMBIO-BLOCKED'
		BEGIN
			SELECT RAISE(ABORT, 'entrada bloqueada');
		END;
	`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin cambio: %v", err)
	}
	_, err = applyCambioInventory(tx, cambioInventoryInput{
		ProductID:         "P-CAMBIO-ROLLBACK",
		OutgoingUnitIDs:   []string{"U-P-CAMBIO-ROLLBACK-01"},
		IncomingProductID: "P-CAMBIO-BLOCKED",
		IncomingNew:       true,
		IncomingName:      "Producto bloqueado",
		IncomingQuantity:  2,
		MovementNote:      "debe revertirse",
		Now:               "2026-08-07T12:00:00Z",
	})
	if err == nil {
		_ = tx.Rollback()
		t.Fatal("expected incoming failure")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback cambio: %v", err)
	}
	if availableCambioCount(t, db, "P-CAMBIO-ROLLBACK") != 2 || totalCambioCount(t, db, "P-CAMBIO-ROLLBACK") != 2 {
		t.Fatalf("outgoing deletion was not rolled back")
	}
	var productCount, movementCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = 'P-CAMBIO-BLOCKED'`).Scan(&productCount); err != nil {
		t.Fatalf("count rolled back product: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM movimientos WHERE producto_id = 'P-CAMBIO-BLOCKED'`).Scan(&movementCount); err != nil {
		t.Fatalf("count rolled back movements: %v", err)
	}
	if productCount != 0 || movementCount != 0 {
		t.Fatalf("incoming changes survived rollback: products=%d movements=%d", productCount, movementCount)
	}
}

func TestApplyCambioInventoryRejectsUnavailableOutgoing(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-CAMBIO-RESERVED", 1)
	seedCambioProduct(t, db, "P-CAMBIO-IN", 1)
	if _, err := db.Exec(`UPDATE unidades SET estado = 'Reservada' WHERE id = 'U-P-CAMBIO-RESERVED-01'`); err != nil {
		t.Fatalf("reserve outgoing unit: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin cambio: %v", err)
	}
	_, err = applyCambioInventory(tx, cambioInventoryInput{
		ProductID:         "P-CAMBIO-RESERVED",
		OutgoingUnitIDs:   []string{"U-P-CAMBIO-RESERVED-01"},
		IncomingProductID: "P-CAMBIO-IN",
		IncomingQuantity:  1,
		MovementNote:      "unidad no disponible",
		Now:               "2026-08-07T12:00:00Z",
	})
	if err != errInsufficientStock {
		_ = tx.Rollback()
		t.Fatalf("expected insufficient stock, got %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback unavailable cambio: %v", err)
	}
	var state string
	if err := db.QueryRow(`SELECT estado FROM unidades WHERE id = 'U-P-CAMBIO-RESERVED-01'`).Scan(&state); err != nil {
		t.Fatalf("query reserved unit: %v", err)
	}
	if state != "Reservada" || availableCambioCount(t, db, "P-CAMBIO-IN") != 1 {
		t.Fatalf("unavailable outgoing was changed unexpectedly: state=%q", state)
	}
}

func TestApplyCambioInventoryMultiProcessesMultipleLines(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-MULTI-OUT-A", 2)
	seedCambioProduct(t, db, "P-MULTI-OUT-B", 3)
	seedCambioProduct(t, db, "P-MULTI-IN-A", 1)
	seedCambioProduct(t, db, "P-MULTI-IN-B", 0)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin multi cambio: %v", err)
	}
	result, err := applyCambioInventoryMulti(tx, cambioMultiInput{
		Salientes: []cambioLineInput{
			{ProductoID: "P-MULTI-OUT-A", Cantidad: 1},
			{ProductoID: "P-MULTI-OUT-B", Cantidad: 2},
		},
		Entrantes: []cambioLineInput{
			{ProductoID: "P-MULTI-IN-A", Cantidad: 2},
			{ProductoID: "P-MULTI-IN-B", Cantidad: 3},
		},
		PersonaCambio: "Cliente multi",
		Notas:         "varios productos",
		MovementNote:  "cliente multi",
		User:          &User{Username: "tester", Role: "admin"},
		Now:           "2026-08-08T12:00:00Z",
	})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("applyCambioInventoryMulti: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit multi cambio: %v", err)
	}

	if len(result.SalienteUnitIDs) != 3 || len(result.EntranteUnitIDs) != 5 || result.OperationID == 0 {
		t.Fatalf("unexpected multi cambio result: %+v", result)
	}
	if availableCambioCount(t, db, "P-MULTI-OUT-A") != 1 || availableCambioCount(t, db, "P-MULTI-OUT-B") != 1 {
		t.Fatalf("outgoing quantities were not reduced")
	}
	if availableCambioCount(t, db, "P-MULTI-IN-A") != 3 || availableCambioCount(t, db, "P-MULTI-IN-B") != 3 {
		t.Fatalf("incoming quantities were not increased")
	}
	if movementCambioCount(t, db, "cambio_salida", "P-MULTI-OUT-A") != 1 ||
		movementCambioCount(t, db, "cambio_salida", "P-MULTI-OUT-B") != 2 ||
		movementCambioCount(t, db, "cambio_entrada", "P-MULTI-IN-A") != 2 ||
		movementCambioCount(t, db, "cambio_entrada", "P-MULTI-IN-B") != 3 {
		t.Fatalf("unexpected multi movement counts")
	}
	rows, err := db.Query(`
		SELECT direccion, producto_id, cantidad, es_nuevo
		FROM cambio_operacion_items
		WHERE operacion_id = ?
		ORDER BY orden`, result.OperationID)
	if err != nil {
		t.Fatalf("query multi items: %v", err)
	}
	defer rows.Close()
	type itemRow struct {
		direccion string
		sku       string
		cantidad  int
		esNuevo   int
	}
	items := []itemRow{}
	for rows.Next() {
		var item itemRow
		if err := rows.Scan(&item.direccion, &item.sku, &item.cantidad, &item.esNuevo); err != nil {
			t.Fatalf("scan multi item: %v", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}
	if len(items) != 4 ||
		items[0].direccion != "salida" || items[0].sku != "P-MULTI-OUT-A" || items[0].cantidad != 1 ||
		items[1].direccion != "salida" || items[1].sku != "P-MULTI-OUT-B" || items[1].cantidad != 2 ||
		items[2].direccion != "entrada" || items[2].sku != "P-MULTI-IN-A" || items[2].cantidad != 2 ||
		items[3].direccion != "entrada" || items[3].sku != "P-MULTI-IN-B" || items[3].cantidad != 3 || items[3].esNuevo != 0 {
		t.Fatalf("unexpected multi items: %+v", items)
	}

	var persona, outgoingName, incomingName string
	var outgoingQty, incomingQty int
	if err := db.QueryRow(`
		SELECT persona_cambio, saliente_producto_nombre, saliente_cantidad,
		       entrante_producto_nombre, entrante_cantidad
		FROM cambio_operaciones WHERE id = ?`, result.OperationID).Scan(
		&persona, &outgoingName, &outgoingQty, &incomingName, &incomingQty); err != nil {
		t.Fatalf("query multi header: %v", err)
	}
	if persona != "Cliente multi" || outgoingName != "Producto P-MULTI-OUT-A" || outgoingQty != 1 ||
		incomingName != "Producto P-MULTI-IN-A" || incomingQty != 2 {
		t.Fatalf("unexpected multi header: persona=%q out=%q/%d in=%q/%d", persona, outgoingName, outgoingQty, incomingName, incomingQty)
	}
}

func TestApplyCambioInventoryMultiCreatesMultipleNewIncoming(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-MULTI-OUT", 2)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin multi new: %v", err)
	}
	_, err = applyCambioInventoryMulti(tx, cambioMultiInput{
		Salientes: []cambioLineInput{
			{ProductoID: "P-MULTI-OUT", Cantidad: 1},
		},
		Entrantes: []cambioLineInput{
			{ProductoID: "P-MULTI-NEW-A", Cantidad: 2, EsNuevo: true, Nombre: "Producto nuevo A", Linea: "Cambios"},
			{ProductoID: "P-MULTI-NEW-B", Cantidad: 1, EsNuevo: true, Nombre: "Producto nuevo B"},
		},
		PersonaCambio: "Cliente nuevo",
		MovementNote:  "productos nuevos",
		Now:           "2026-08-08T13:00:00Z",
	})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("applyCambioInventoryMulti new products: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit multi new: %v", err)
	}

	var productCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku IN ('P-MULTI-NEW-A', 'P-MULTI-NEW-B')`).Scan(&productCount); err != nil {
		t.Fatalf("count new products: %v", err)
	}
	if productCount != 2 || availableCambioCount(t, db, "P-MULTI-NEW-A") != 2 || availableCambioCount(t, db, "P-MULTI-NEW-B") != 1 {
		t.Fatalf("new incoming products were not created with their units")
	}
	var lineas int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cambio_operacion_items WHERE direccion = 'entrada' AND es_nuevo = 1`).Scan(&lineas); err != nil {
		t.Fatalf("count new incoming items: %v", err)
	}
	if lineas != 2 {
		t.Fatalf("expected two new incoming items, got %d", lineas)
	}
}

func TestApplyCambioInventoryMultiRollsBackOnIncomingFailure(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-MULTI-ROLLBACK", 2)
	if _, err := db.Exec(`
		CREATE TRIGGER fail_multi_cambio_incoming
		BEFORE INSERT ON unidades
		WHEN NEW.producto_id = 'P-MULTI-BLOCKED'
		BEGIN
			SELECT RAISE(ABORT, 'entrada bloqueada');
		END;
	`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin multi rollback: %v", err)
	}
	_, err = applyCambioInventoryMulti(tx, cambioMultiInput{
		Salientes: []cambioLineInput{
			{ProductoID: "P-MULTI-ROLLBACK", Cantidad: 1},
		},
		Entrantes: []cambioLineInput{
			{ProductoID: "P-MULTI-IN-OK", Cantidad: 1},
			{ProductoID: "P-MULTI-BLOCKED", Cantidad: 1, EsNuevo: true, Nombre: "Bloqueado"},
		},
		MovementNote: "debe revertirse",
		Now:          "2026-08-08T14:00:00Z",
	})
	if err == nil {
		_ = tx.Rollback()
		t.Fatal("expected incoming failure")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback multi cambio: %v", err)
	}
	if availableCambioCount(t, db, "P-MULTI-ROLLBACK") != 2 || totalCambioCount(t, db, "P-MULTI-ROLLBACK") != 2 {
		t.Fatalf("outgoing deletion was not rolled back")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku IN ('P-MULTI-IN-OK', 'P-MULTI-BLOCKED')`).Scan(&count); err != nil {
		t.Fatalf("count rolled back products: %v", err)
	}
	if count != 0 {
		t.Fatalf("incoming products survived rollback")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM cambio_operaciones`).Scan(&count); err != nil {
		t.Fatalf("count rolled back operations: %v", err)
	}
	if count != 0 {
		t.Fatalf("operation header survived rollback")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM cambio_operacion_items`).Scan(&count); err != nil {
		t.Fatalf("count rolled back items: %v", err)
	}
	if count != 0 {
		t.Fatalf("operation items survived rollback")
	}
}

func TestApplyCambioInventoryMultiRejectsDuplicateOutgoing(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-MULTI-DUP", 4)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin duplicate cambio: %v", err)
	}
	_, err = applyCambioInventoryMulti(tx, cambioMultiInput{
		Salientes: []cambioLineInput{
			{ProductoID: "P-MULTI-DUP", Cantidad: 1},
			{ProductoID: "P-MULTI-DUP", Cantidad: 1},
		},
		Entrantes: []cambioLineInput{
			{ProductoID: "P-MULTI-DUP", Cantidad: 2},
		},
		MovementNote: "duplicado",
		Now:          "2026-08-08T15:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "repetido") {
		_ = tx.Rollback()
		t.Fatalf("expected duplicate outgoing error, got %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback duplicate cambio: %v", err)
	}
	if availableCambioCount(t, db, "P-MULTI-DUP") != 4 {
		t.Fatalf("duplicate outgoing changed stock")
	}
}

func TestApplyCambioInventoryMultiRejectsNewSKUCollision(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-MULTI-COLLIDE", 1)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin collision cambio: %v", err)
	}
	_, err = applyCambioInventoryMulti(tx, cambioMultiInput{
		Salientes: []cambioLineInput{
			{ProductoID: "P-MULTI-COLLIDE", Cantidad: 1},
		},
		Entrantes: []cambioLineInput{
			{ProductoID: "P-MULTI-COLLIDE", Cantidad: 1, EsNuevo: true, Nombre: "Colisión"},
		},
		MovementNote: "colision",
		Now:          "2026-08-08T16:00:00Z",
	})
	if err != errCambioIncomingSKUExists {
		_ = tx.Rollback()
		t.Fatalf("expected incoming SKU collision, got %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback collision cambio: %v", err)
	}
	if availableCambioCount(t, db, "P-MULTI-COLLIDE") != 1 {
		t.Fatalf("collision changed stock")
	}
}

func TestApplyCambioInventoryMultiRejectsInsufficientStock(t *testing.T) {
	db := setupCambioInventoryDB(t)
	seedCambioProduct(t, db, "P-MULTI-SHORT", 1)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin short cambio: %v", err)
	}
	_, err = applyCambioInventoryMulti(tx, cambioMultiInput{
		Salientes: []cambioLineInput{
			{ProductoID: "P-MULTI-SHORT", Cantidad: 5},
		},
		Entrantes: []cambioLineInput{
			{ProductoID: "P-MULTI-SHORT", Cantidad: 1},
		},
		MovementNote: "sin stock",
		Now:          "2026-08-08T17:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "stock insuficiente para") {
		_ = tx.Rollback()
		t.Fatalf("expected insufficient stock error, got %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback short cambio: %v", err)
	}
	if availableCambioCount(t, db, "P-MULTI-SHORT") != 1 {
		t.Fatalf("insufficient stock changed stock")
	}
}

func TestResetBusinessDataDeletesBusinessTablesAndDisablesDemoSeed(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE productos (sku TEXT PRIMARY KEY);
		CREATE TABLE unidades (id TEXT PRIMARY KEY);
		CREATE TABLE ventas (id INTEGER PRIMARY KEY AUTOINCREMENT);
		CREATE TABLE movimientos (id INTEGER PRIMARY KEY AUTOINCREMENT);
		CREATE TABLE cambios (id INTEGER PRIMARY KEY AUTOINCREMENT);
		CREATE TABLE retomas (id INTEGER PRIMARY KEY AUTOINCREMENT);
		INSERT INTO productos (sku) VALUES ('P-001');
		INSERT INTO unidades (id) VALUES ('U-001');
		INSERT INTO ventas DEFAULT VALUES;
		INSERT INTO movimientos DEFAULT VALUES;
		INSERT INTO cambios DEFAULT VALUES;
		INSERT INTO retomas DEFAULT VALUES;
	`)
	if err != nil {
		t.Fatalf("seed db: %v", err)
	}

	if err := resetBusinessData(db); err != nil {
		t.Fatalf("resetBusinessData: %v", err)
	}

	for _, table := range []string{"productos", "unidades", "ventas", "movimientos", "cambios", "retomas"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("expected %s empty, got %d rows", table, count)
		}
	}
	if !demoSeedDisabled(db) {
		t.Fatalf("expected demo seed disabled")
	}
}

func TestResetUsersDataRecreatesSeedAdminAndClearsSessions(t *testing.T) {
	t.Setenv("ADMIN_USER", "root")
	t.Setenv("ADMIN_PASS", "secret-pass")

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL,
			created_at TEXT NOT NULL,
			is_active INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		);
		INSERT INTO users (username, password_hash, role, created_at, is_active)
		VALUES ('old-admin', 'hash', 'admin', '2024-01-01T00:00:00Z', 1);
		INSERT INTO sessions (token, user_id, created_at, expires_at)
		VALUES ('token', 1, '2024-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
	`)
	if err != nil {
		t.Fatalf("seed db: %v", err)
	}

	if err := resetUsersData(db); err != nil {
		t.Fatalf("resetUsersData: %v", err)
	}

	var userCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("expected one seeded admin, got %d users", userCount)
	}

	var username, role, hash string
	var isActive int
	if err := db.QueryRow(`SELECT username, role, password_hash, is_active FROM users`).Scan(&username, &role, &hash, &isActive); err != nil {
		t.Fatalf("query seeded admin: %v", err)
	}
	if username != "root" || role != "admin" || isActive != 1 {
		t.Fatalf("unexpected seeded admin username=%q role=%q active=%d", username, role, isActive)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("secret-pass")); err != nil {
		t.Fatalf("seeded admin password mismatch: %v", err)
	}

	var sessionCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessionCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessionCount != 0 {
		t.Fatalf("expected sessions empty, got %d", sessionCount)
	}
}

func TestLoginRateLimiterBlocksAndResets(t *testing.T) {
	now := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	limiter := newLoginRateLimiter()
	limiter.now = func() time.Time { return now }
	key := "127.0.0.1\x00admin"

	for i := 0; i < limiter.maxFailures; i++ {
		allowed, _ := limiter.allow(key)
		if !allowed {
			t.Fatalf("attempt %d should still be allowed before the limit", i+1)
		}
		limiter.recordFailure(key)
	}

	allowed, retryAfter := limiter.allow(key)
	if allowed || retryAfter <= 0 {
		t.Fatalf("expected limiter block, allowed=%v retry=%v", allowed, retryAfter)
	}

	now = now.Add(limiter.block + time.Second)
	allowed, _ = limiter.allow(key)
	if !allowed {
		t.Fatalf("expected attempt to be allowed after block expires")
	}
	limiter.recordSuccess(key)
	for i := 0; i < limiter.maxFailures; i++ {
		limiter.recordFailure(key)
	}
	if allowed, _ := limiter.allow(key); allowed {
		t.Fatalf("expected limiter to track failures after reset")
	}
}

func TestCSRFMiddlewareRequiresSessionToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := csrfMiddleware(next)
	user := &User{CSRFToken: "csrf-token"}

	missing := httptest.NewRequest(http.MethodPost, "/venta", nil)
	missing = missing.WithContext(context.WithValue(missing.Context(), userContextKey, user))
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusForbidden {
		t.Fatalf("expected missing token to be forbidden, got %d", missingResponse.Code)
	}

	ajaxMissing := httptest.NewRequest(http.MethodPost, "/venta", nil)
	ajaxMissing.Header.Set("Accept", "application/json")
	ajaxMissing = ajaxMissing.WithContext(context.WithValue(ajaxMissing.Context(), userContextKey, user))
	ajaxMissingResponse := httptest.NewRecorder()
	handler.ServeHTTP(ajaxMissingResponse, ajaxMissing)
	if ajaxMissingResponse.Code != http.StatusForbidden || !bytes.Contains(ajaxMissingResponse.Body.Bytes(), []byte(`"ok":false`)) {
		t.Fatalf("expected JSON CSRF error, got status=%d body=%q", ajaxMissingResponse.Code, ajaxMissingResponse.Body.String())
	}

	valid := httptest.NewRequest(http.MethodPost, "/venta", nil)
	valid.Header.Set("X-CSRF-Token", "csrf-token")
	valid = valid.WithContext(context.WithValue(valid.Context(), userContextKey, user))
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("expected valid token to pass, got %d", validResponse.Code)
	}
}

func TestAuthMiddlewareReturnsJSONForExpiredAjaxSession(t *testing.T) {
	db := setupCambioInventoryDB(t)
	defer db.Close()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("authenticated handler should not be called")
	})
	handler := authMiddleware(db, next)
	request := httptest.NewRequest(http.MethodPost, "/carrito/items/cambio-pair", nil)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || !bytes.Contains(response.Body.Bytes(), []byte(`"ok":false`)) {
		t.Fatalf("expected JSON auth error, got status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestInitDBLeavesNewDatabaseEmptyUnlessDemoIsExplicit(t *testing.T) {
	t.Setenv("SEED_DEMO", "")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")

	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	defer db.Close()

	for _, table := range []string{"productos", "unidades", "ventas"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("expected new database table %s to be empty, got %d", table, count)
		}
	}
	var migrationCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = 1").Scan(&migrationCount); err != nil {
		t.Fatalf("schema migration: %v", err)
	}
	if migrationCount != 1 {
		t.Fatalf("expected legacy migration to be recorded once, got %d", migrationCount)
	}
	if err := db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatalf("latest schema migration: %v", err)
	}
	if migrationCount != 9 {
		t.Fatalf("expected schema migration version 9, got %d", migrationCount)
	}
}

func TestInitDBSeedsOnlyWithExplicitDemoFlag(t *testing.T) {
	t.Setenv("SEED_DEMO", "1")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")

	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	defer db.Close()

	for _, table := range []string{"unidades", "ventas"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count == 0 {
			t.Fatalf("expected explicit demo seed to populate %s", table)
		}
	}
}

func TestCancelSaleReplenishesLinkedUnitsAndKeepsHistory(t *testing.T) {
	t.Setenv("SEED_DEMO", "")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")
	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		INSERT INTO productos (sku, id, linea, nombre, precio_venta_cop) VALUES ('P-900', 'P-900', 'Test', 'Producto test', 12000);
		INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES ('U-900', 'P-900', 'Vendida', '2026-08-06T12:00:00Z');
		INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop)
		VALUES ('P-900', 1, 12000, 'Efectivo', '', '2026-08-06T12:00:00Z', 12000, 12000);
	`)
	if err != nil {
		t.Fatalf("seed sale: %v", err)
	}
	var saleID int
	if err := db.QueryRow(`SELECT id FROM ventas WHERE producto_id = 'P-900'`).Scan(&saleID); err != nil {
		t.Fatalf("sale id: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO venta_unidades (venta_id, unidad_id) VALUES (?, 'U-900')`, saleID); err != nil {
		t.Fatalf("link sale unit: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := cancelSale(tx, saleID, &User{Username: "root", Role: "admin"}, "error de captura"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("cancelSale: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var state string
	if err := db.QueryRow(`SELECT estado FROM ventas WHERE id = ?`, saleID).Scan(&state); err != nil {
		t.Fatalf("sale state: %v", err)
	}
	if state != "anulada" {
		t.Fatalf("expected annulled sale, got %q", state)
	}
	if err := db.QueryRow(`SELECT estado FROM unidades WHERE id = 'U-900'`).Scan(&state); err != nil {
		t.Fatalf("unit state: %v", err)
	}
	if state != "Disponible" {
		t.Fatalf("expected replenished unit, got %q", state)
	}
	var linkCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM venta_unidades WHERE venta_id = ?`, saleID).Scan(&linkCount); err != nil {
		t.Fatalf("count sale links: %v", err)
	}
	if linkCount != 0 {
		t.Fatalf("expected cancelled sale links to be cleared, got %d", linkCount)
	}
	var movementType string
	if err := db.QueryRow(`SELECT tipo FROM movimientos WHERE unidad_id = 'U-900' ORDER BY id DESC LIMIT 1`).Scan(&movementType); err != nil {
		t.Fatalf("movement: %v", err)
	}
	if movementType != "anulacion_venta" {
		t.Fatalf("expected cancellation movement, got %q", movementType)
	}
	var auditType, auditUser string
	if err := db.QueryRow(`SELECT event_type, username FROM audit_events WHERE entity_id = ?`, saleID).Scan(&auditType, &auditUser); err != nil {
		t.Fatalf("audit event: %v", err)
	}
	if auditType != "sale.cancel" || auditUser != "root" {
		t.Fatalf("unexpected audit event type=%q user=%q", auditType, auditUser)
	}
}

func TestCancelledSaleUnitsCanBeResoldAndStockReduced(t *testing.T) {
	t.Setenv("SEED_DEMO", "")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")
	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		INSERT INTO productos (sku, id, linea, nombre, precio_venta_cop) VALUES ('P-910', 'P-910', 'Test', 'Producto reventa', 12000);
		INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES
			('U-910A', 'P-910', 'Vendida', '2026-08-06T12:00:00Z'),
			('U-910B', 'P-910', 'Vendida', '2026-08-06T12:01:00Z');
		INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop)
		VALUES ('P-910', 2, 24000, 'Efectivo', '', '2026-08-06T12:00:00Z', 12000, 24000);
	`); err != nil {
		t.Fatalf("seed sale: %v", err)
	}
	var saleID int
	if err := db.QueryRow(`SELECT id FROM ventas WHERE producto_id = 'P-910'`).Scan(&saleID); err != nil {
		t.Fatalf("sale id: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO venta_unidades (venta_id, unidad_id) VALUES (?, 'U-910A'), (?, 'U-910B')`, saleID, saleID); err != nil {
		t.Fatalf("link sale units: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin cancel: %v", err)
	}
	if err := cancelSale(tx, saleID, &User{Username: "root", Role: "admin"}, "prueba de reventa"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("cancelSale: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit cancel: %v", err)
	}

	// La unidad anulada puede revenderse (antes fallaba por UNIQUE en venta_unidades).
	resale, err := db.Exec(`
		INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop)
		VALUES ('P-910', 1, 12000, 'Efectivo', '', '2026-08-07T12:00:00Z', 12000, 12000);
	`)
	if err != nil {
		t.Fatalf("resale venta: %v", err)
	}
	resaleID, err := resale.LastInsertId()
	if err != nil {
		t.Fatalf("resale id: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO venta_unidades (venta_id, unidad_id) VALUES (?, 'U-910A')`, resaleID); err != nil {
		t.Fatalf("resell cancelled unit: %v", err)
	}

	// La reducción de stock puede borrar la otra unidad repuesta (antes fallaba por FK RESTRICT).
	tx, err = db.Begin()
	if err != nil {
		t.Fatalf("begin stock edit: %v", err)
	}
	if _, err := deleteSpecificAvailableUnits(tx, "P-910", []string{"U-910B"}); err != nil {
		_ = tx.Rollback()
		t.Fatalf("delete replenished unit: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit stock edit: %v", err)
	}

	var remaining int
	if err := db.QueryRow(`SELECT COUNT(*) FROM unidades WHERE id = 'U-910B'`).Scan(&remaining); err != nil {
		t.Fatalf("count deleted unit: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected replenished unit to be deleted, got %d", remaining)
	}
}

func TestMigrationRepairsAnnulledSaleLinks(t *testing.T) {
	t.Setenv("SEED_DEMO", "")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")
	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		INSERT INTO productos (sku, id, linea, nombre) VALUES ('P-920', 'P-920', 'Test', 'Producto legacy');
		INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES
			('U-920A', 'P-920', 'Disponible', '2026-08-06T12:00:00Z'),
			('U-920B', 'P-920', 'Vendida', '2026-08-06T12:01:00Z');
		INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop, estado)
		VALUES ('P-920', 1, 0, 'Efectivo', '', '2026-08-06T12:00:00Z', 0, 0, 'anulada');
		INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop, estado)
		VALUES ('P-920', 1, 0, 'Efectivo', '', '2026-08-06T12:01:00Z', 0, 0, 'confirmada');
	`); err != nil {
		t.Fatalf("seed legacy state: %v", err)
	}
	var annulledID, confirmedID int
	if err := db.QueryRow(`SELECT id FROM ventas WHERE estado = 'anulada'`).Scan(&annulledID); err != nil {
		t.Fatalf("annulled id: %v", err)
	}
	if err := db.QueryRow(`SELECT id FROM ventas WHERE estado = 'confirmada'`).Scan(&confirmedID); err != nil {
		t.Fatalf("confirmed id: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO venta_unidades (venta_id, unidad_id) VALUES (?, 'U-920A'), (?, 'U-920B')`, annulledID, confirmedID); err != nil {
		t.Fatalf("link legacy units: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin migration: %v", err)
	}
	if err := migrateVentaUnidadesRepairSchema(tx); err != nil {
		_ = tx.Rollback()
		t.Fatalf("migrateVentaUnidadesRepairSchema: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit migration: %v", err)
	}

	var annulledLinks, confirmedLinks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM venta_unidades WHERE venta_id = ?`, annulledID).Scan(&annulledLinks); err != nil {
		t.Fatalf("count annulled links: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM venta_unidades WHERE venta_id = ?`, confirmedID).Scan(&confirmedLinks); err != nil {
		t.Fatalf("count confirmed links: %v", err)
	}
	if annulledLinks != 0 || confirmedLinks != 1 {
		t.Fatalf("unexpected links after repair: annulled=%d confirmed=%d", annulledLinks, confirmedLinks)
	}
}

func TestParseCOPIntegerRejectsDecimals(t *testing.T) {
	valid := map[string]int{"12000": 12000, "$12.000": 12000, "12,000": 12000}
	for raw, expected := range valid {
		value, err := parseCOPInteger(raw)
		if err != nil || value != expected {
			t.Fatalf("parseCOPInteger(%q) = %d, %v; expected %d", raw, value, err, expected)
		}
	}
	for _, raw := range []string{"12000.50", "12,00", "-12000", "abc"} {
		if _, err := parseCOPInteger(raw); err == nil {
			t.Fatalf("expected decimal or invalid value %q to be rejected", raw)
		}
	}
}

func TestInventoryIntegrityTriggersRejectOrphanUnits(t *testing.T) {
	t.Setenv("SEED_DEMO", "")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")
	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO productos (sku, id, linea, nombre) VALUES ('P-901', 'P-901', 'Test', 'Producto test')`); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	if err := ensureInventoryIntegrityTriggers(db); err != nil {
		t.Fatalf("ensure triggers: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES ('U-ORPHAN', 'P-404', 'Disponible', '2026-08-06T12:00:00Z')`); err == nil {
		t.Fatalf("expected orphan unit insertion to fail")
	}
	if _, err := db.Exec(`INSERT INTO unidades (id, producto_id, estado, creado_en) VALUES ('U-901', 'P-901', 'Disponible', '2026-08-06T12:00:00Z')`); err != nil {
		t.Fatalf("valid unit insertion: %v", err)
	}
	if _, err := db.Exec(`UPDATE productos SET precio_venta_cop = -1 WHERE sku = 'P-901'`); err == nil {
		t.Fatalf("expected negative COP price update to fail")
	}
}

func TestDashboardUsesExactCOPTotalsAndExcludesCancelledSales(t *testing.T) {
	t.Setenv("SEED_DEMO", "")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")
	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO productos (sku, id, linea, nombre) VALUES ('P-902', 'P-902', 'Test', 'Producto dashboard')`); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	_, err = db.Exec(`
		INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop, estado)
		VALUES ('P-902', 3, 333, 'Efectivo', '', '2026-08-06T12:00:00Z', 333, 1001, 'confirmada');
		INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, notas, fecha, precio_unitario_cop, total_cop, estado)
		VALUES ('P-902', 1, 2000, 'Efectivo', '', '2026-08-06T13:00:00Z', 2000, 2000, 'anulada');
	`)
	if err != nil {
		t.Fatalf("insert sales: %v", err)
	}
	start := time.Date(2026, time.August, 6, 0, 0, 0, 0, time.UTC)
	data, err := buildDashboardData(db, "2026-08-06", "2026-08-06", start, start)
	if err != nil {
		t.Fatalf("build dashboard: %v", err)
	}
	if data.RangeTotal != "$1.001" || data.RangeCount != 1 {
		t.Fatalf("unexpected dashboard total=%q count=%d", data.RangeTotal, data.RangeCount)
	}
	if len(data.Sales) != 1 || data.Sales[0].Total != "$1.001" {
		t.Fatalf("unexpected dashboard sales: %+v", data.Sales)
	}
}

func TestDashboardIncludesStructuredChangesByOperationAndDate(t *testing.T) {
	t.Setenv("SEED_DEMO", "")
	t.Setenv("ADMIN_USER", "")
	t.Setenv("ADMIN_PASS", "")
	db, err := initDB(filepath.Join(t.TempDir(), "data.db"), []string{"Efectivo"})
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		INSERT INTO cambio_operaciones (
			fecha, persona_cambio, notas,
			saliente_producto_id, saliente_producto_nombre, saliente_cantidad,
			entrante_producto_id, entrante_producto_nombre, entrante_cantidad,
			usuario
		) VALUES
			('2026-08-06T10:00:00Z', 'Cliente uno', 'Talla incorrecta', 'P-OUT', 'Producto que sale', 2, 'P-IN', 'Producto que entra', 1, 'admin'),
			('2026-08-06T11:00:00Z', 'Cliente dos', 'Cambio de referencia', 'P-OUT-2', 'Otro saliente', 1, 'P-IN-2', 'Otro entrante', 1, 'admin'),
			('2026-08-07T10:00:00Z', 'Fuera de rango', 'No debe aparecer', 'P-OLD', 'Antiguo', 1, 'P-NEW', 'Nuevo', 1, 'admin')
	`)
	if err != nil {
		t.Fatalf("insert changes: %v", err)
	}

	start := time.Date(2026, time.August, 6, 0, 0, 0, 0, time.UTC)
	end := start
	data, err := buildDashboardData(db, "2026-08-06", "2026-08-06", start, end)
	if err != nil {
		t.Fatalf("build dashboard: %v", err)
	}
	if data.ChangeCount != 2 || len(data.Changes) != 2 {
		t.Fatalf("unexpected change summary count=%d rows=%d", data.ChangeCount, len(data.Changes))
	}
	if data.Changes[0].Persona != "Cliente dos" || data.Changes[0].SalienteProducto != "Otro saliente" || data.Changes[0].EntranteProducto != "Otro entrante" {
		t.Fatalf("unexpected latest change: %+v", data.Changes[0])
	}
	if len(data.Timeline) != 1 || data.Timeline[0].Cambios != 2 {
		t.Fatalf("unexpected timeline changes: %+v", data.Timeline)
	}
}

func seedCheckoutUser(t *testing.T, db *sql.DB, username string) int {
	t.Helper()
	result, err := db.Exec(`
		INSERT INTO users (username, password_hash, role, created_at, is_active)
		VALUES (?, 'test-hash', 'empleado', ?, 1)`, username, time.Now().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert checkout user: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("checkout user id: %v", err)
	}
	return int(id)
}

func seedCheckoutPricedProduct(t *testing.T, db *sql.DB, sku string, quantity int, price int64) {
	t.Helper()
	seedCambioProduct(t, db, sku, quantity)
	if _, err := db.Exec(`UPDATE productos SET precio_venta_cop = ? WHERE sku = ?`, price, sku); err != nil {
		t.Fatalf("set checkout price %s: %v", sku, err)
	}
}

func TestCheckoutKeepsDraftsIsolatedByUser(t *testing.T) {
	db := setupCambioInventoryDB(t)
	userOne := seedCheckoutUser(t, db, "checkout-one")
	userTwo := seedCheckoutUser(t, db, "checkout-two")
	seedCheckoutPricedProduct(t, db, "P-CART", 3, 12000)

	itemID, err := addCheckoutSaleItem(db, userOne, checkoutSaleInput{
		ProductoID: "P-CART",
		Cantidad:   1,
	})
	if err != nil {
		t.Fatalf("add checkout item one: %v", err)
	}
	if itemID == 0 {
		t.Fatal("expected checkout item id")
	}
	if _, err := addCheckoutSaleItem(db, userTwo, checkoutSaleInput{
		ProductoID: "P-CART",
		Cantidad:   2,
	}); err != nil {
		t.Fatalf("add checkout item two: %v", err)
	}

	checkoutOne, salesOne, _, err := loadActiveCheckout(db, userOne)
	if err != nil {
		t.Fatalf("load checkout one: %v", err)
	}
	checkoutTwo, salesTwo, _, err := loadActiveCheckout(db, userTwo)
	if err != nil {
		t.Fatalf("load checkout two: %v", err)
	}
	if checkoutOne.ID == checkoutTwo.ID || len(salesOne) != 1 || len(salesTwo) != 1 {
		t.Fatalf("checkout drafts were not isolated: one=%+v/%d two=%+v/%d", checkoutOne, len(salesOne), checkoutTwo, len(salesTwo))
	}
}

func TestProcessCheckoutLeavesUnavailableLinesForRetry(t *testing.T) {
	db := setupCambioInventoryDB(t)
	userID := seedCheckoutUser(t, db, "checkout-partial")
	seedCheckoutPricedProduct(t, db, "P-CHECKOUT-OK", 1, 10000)
	seedCheckoutPricedProduct(t, db, "P-CHECKOUT-LATER", 0, 15000)

	if _, err := addCheckoutSaleItem(db, userID, checkoutSaleInput{ProductoID: "P-CHECKOUT-OK", Cantidad: 1}); err != nil {
		t.Fatalf("add available sale: %v", err)
	}
	if _, err := addCheckoutSaleItem(db, userID, checkoutSaleInput{ProductoID: "P-CHECKOUT-LATER", Cantidad: 1}); err != nil {
		t.Fatalf("add unavailable sale: %v", err)
	}
	checkout, _, _, err := loadActiveCheckout(db, userID)
	if err != nil {
		t.Fatalf("load partial checkout: %v", err)
	}

	result, err := processCheckout(db, userID, checkout.ID, "Cliente parcial", "Efectivo", "", &User{ID: userID, Username: "checkout-partial"})
	if err != nil {
		t.Fatalf("process partial checkout: %v", err)
	}
	if result.State != checkoutStatePartial || result.ProcessedCount != 1 || result.FailedCount != 1 {
		t.Fatalf("unexpected partial result: %+v", result)
	}
	if availableCambioCount(t, db, "P-CHECKOUT-OK") != 0 || availableCambioCount(t, db, "P-CHECKOUT-LATER") != 0 {
		t.Fatalf("unexpected stock after partial checkout")
	}

	if _, err := db.Exec(`
		INSERT INTO unidades (id, producto_id, estado, creado_en)
		VALUES ('U-P-CHECKOUT-LATER-01', 'P-CHECKOUT-LATER', 'Disponible', ?)`, time.Now().Format(time.RFC3339)); err != nil {
		t.Fatalf("add retry stock: %v", err)
	}
	result, err = processCheckout(db, userID, checkout.ID, "Cliente parcial", "Efectivo", "", &User{ID: userID, Username: "checkout-partial"})
	if err != nil {
		t.Fatalf("retry partial checkout: %v", err)
	}
	if result.State != checkoutStateConfirmed || result.PendingCount != 0 {
		t.Fatalf("unexpected retry result: %+v", result)
	}
	var salesCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ventas WHERE checkout_id = ? AND estado = 'confirmada'`, checkout.ID).Scan(&salesCount); err != nil {
		t.Fatalf("count checkout sales: %v", err)
	}
	if salesCount != 2 {
		t.Fatalf("expected two confirmed sales after retry, got %d", salesCount)
	}
}

func TestCheckoutCargoDoesNotConsumeInventory(t *testing.T) {
	db := setupCambioInventoryDB(t)
	userID := seedCheckoutUser(t, db, "checkout-cargo")
	if _, err := addCheckoutSaleItem(db, userID, checkoutSaleInput{
		Tipo:     "cargo",
		TotalCOP: 2500,
		Notas:    "Diferencia de cambio",
	}); err != nil {
		t.Fatalf("add checkout cargo: %v", err)
	}
	checkout, _, _, err := loadActiveCheckout(db, userID)
	if err != nil {
		t.Fatalf("load cargo checkout: %v", err)
	}
	result, err := processCheckout(db, userID, checkout.ID, "Cliente cargo", "Transferencia", "", &User{ID: userID, Username: "checkout-cargo"})
	if err != nil {
		t.Fatalf("process cargo checkout: %v", err)
	}
	if result.State != checkoutStateConfirmed || result.ProcessedTotalCOP != 2500 {
		t.Fatalf("unexpected cargo result: %+v", result)
	}
	var kind, name string
	var quantity, total int
	if err := db.QueryRow(`
		SELECT tipo, producto_nombre, cantidad, total_cop
		FROM ventas WHERE checkout_id = ?`, checkout.ID).Scan(&kind, &name, &quantity, &total); err != nil {
		t.Fatalf("query cargo sale: %v", err)
	}
	if kind != "cargo" || name != "Diferencia de cambio" || quantity != 1 || total != 2500 {
		t.Fatalf("unexpected cargo sale: %s/%s/%d/%d", kind, name, quantity, total)
	}
}

func TestCheckoutProcessesGeneralChangeListsIndependently(t *testing.T) {
	db := setupCambioInventoryDB(t)
	userID := seedCheckoutUser(t, db, "checkout-change")
	seedCheckoutPricedProduct(t, db, "P-CHECKOUT-OUT", 2, 10000)
	seedCheckoutPricedProduct(t, db, "P-CHECKOUT-IN", 0, 12000)
	if _, err := addCheckoutChangeItem(db, userID, checkoutChangeInput{
		Direccion:  "salida",
		ProductoID: "P-CHECKOUT-OUT",
		Cantidad:   1,
	}); err != nil {
		t.Fatalf("add outgoing change: %v", err)
	}
	if _, err := addCheckoutChangeItem(db, userID, checkoutChangeInput{
		Direccion:  "entrada",
		ProductoID: "P-CHECKOUT-IN",
		Cantidad:   3,
	}); err != nil {
		t.Fatalf("add incoming change: %v", err)
	}
	checkout, _, _, err := loadActiveCheckout(db, userID)
	if err != nil {
		t.Fatalf("load change checkout: %v", err)
	}
	result, err := processCheckout(db, userID, checkout.ID, "Cliente cambio", "Efectivo", "", &User{ID: userID, Username: "checkout-change"})
	if err != nil {
		t.Fatalf("process change checkout: %v", err)
	}
	if result.State != checkoutStateConfirmed || availableCambioCount(t, db, "P-CHECKOUT-OUT") != 1 || availableCambioCount(t, db, "P-CHECKOUT-IN") != 3 {
		t.Fatalf("unexpected change checkout result: %+v", result)
	}
	var processed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM checkout_cambio_items WHERE checkout_id = ? AND estado = 'procesada'`, checkout.ID).Scan(&processed); err != nil {
		t.Fatalf("count processed change items: %v", err)
	}
	if processed != 2 {
		t.Fatalf("expected both change lists processed, got %d", processed)
	}
}

func TestAddCheckoutChangePairCommitsBothLines(t *testing.T) {
	db := setupCambioInventoryDB(t)
	userID := seedCheckoutUser(t, db, "checkout-change-pair")
	seedCheckoutPricedProduct(t, db, "P-PAIR-OUT", 2, 10000)
	seedCheckoutPricedProduct(t, db, "P-PAIR-IN", 0, 12000)

	err := addCheckoutChangePair(db, userID,
		checkoutChangeInput{Direccion: "salida", ProductoID: "P-PAIR-OUT", Cantidad: 1},
		checkoutChangeInput{Direccion: "entrada", ProductoID: "P-PAIR-IN", Cantidad: 3},
	)
	if err != nil {
		t.Fatalf("add checkout change pair: %v", err)
	}

	checkout, _, changeItems, err := loadActiveCheckout(db, userID)
	if err != nil {
		t.Fatalf("load paired checkout: %v", err)
	}
	if checkout.ID == 0 || len(changeItems) != 2 {
		t.Fatalf("expected two paired change lines, checkout=%+v items=%d", checkout, len(changeItems))
	}
	if changeItems[0].Direccion != "salida" || changeItems[0].ProductoID != "P-PAIR-OUT" || changeItems[0].Cantidad != 1 ||
		changeItems[1].Direccion != "entrada" || changeItems[1].ProductoID != "P-PAIR-IN" || changeItems[1].Cantidad != 3 {
		t.Fatalf("unexpected paired change lines: %+v", changeItems)
	}
}

func TestAddCheckoutChangePairRollsBackWhenIncomingIsInvalid(t *testing.T) {
	db := setupCambioInventoryDB(t)
	userID := seedCheckoutUser(t, db, "checkout-change-pair-rollback")
	seedCheckoutPricedProduct(t, db, "P-PAIR-ROLLBACK", 2, 10000)

	err := addCheckoutChangePair(db, userID,
		checkoutChangeInput{Direccion: "salida", ProductoID: "P-PAIR-ROLLBACK", Cantidad: 1},
		checkoutChangeInput{Direccion: "entrada", ProductoID: "P-DOES-NOT-EXIST", Cantidad: 1},
	)
	if err == nil {
		t.Fatal("expected invalid incoming product to fail")
	}

	var checkoutCount, itemCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM checkout_operaciones WHERE user_id = ?`, userID).Scan(&checkoutCount); err != nil {
		t.Fatalf("count rolled back checkouts: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM checkout_cambio_items`).Scan(&itemCount); err != nil {
		t.Fatalf("count rolled back change items: %v", err)
	}
	if checkoutCount != 0 || itemCount != 0 {
		t.Fatalf("paired change was partially persisted: checkouts=%d items=%d", checkoutCount, itemCount)
	}
}

func TestDashboardIncludesCheckoutCargoAndGeneralChange(t *testing.T) {
	db := setupCambioInventoryDB(t)
	userID := seedCheckoutUser(t, db, "checkout-dashboard")
	seedCheckoutPricedProduct(t, db, "P-DASH-OUT", 2, 10000)
	seedCheckoutPricedProduct(t, db, "P-DASH-IN", 0, 12000)
	if _, err := addCheckoutSaleItem(db, userID, checkoutSaleInput{Tipo: "cargo", TotalCOP: 3000}); err != nil {
		t.Fatalf("add dashboard cargo: %v", err)
	}
	if _, err := addCheckoutChangeItem(db, userID, checkoutChangeInput{Direccion: "salida", ProductoID: "P-DASH-OUT", Cantidad: 1}); err != nil {
		t.Fatalf("add dashboard outgoing: %v", err)
	}
	if _, err := addCheckoutChangeItem(db, userID, checkoutChangeInput{Direccion: "entrada", ProductoID: "P-DASH-IN", Cantidad: 2}); err != nil {
		t.Fatalf("add dashboard incoming: %v", err)
	}
	checkout, _, _, err := loadActiveCheckout(db, userID)
	if err != nil {
		t.Fatalf("load dashboard checkout: %v", err)
	}
	if _, err := processCheckout(db, userID, checkout.ID, "Cliente dashboard", "Efectivo", "Cambio general", &User{ID: userID, Username: "checkout-dashboard"}); err != nil {
		t.Fatalf("process dashboard checkout: %v", err)
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	date := today.Format("2006-01-02")
	data, err := buildDashboardData(db, date, date, today, today)
	if err != nil {
		t.Fatalf("build checkout dashboard: %v", err)
	}
	if data.RangeCount != 1 || data.RangeTotal != "$3.000" {
		t.Fatalf("unexpected checkout dashboard totals: count=%d total=%s", data.RangeCount, data.RangeTotal)
	}
	if len(data.Sales) == 0 || data.Sales[0].Tipo != "Cargo" || data.Sales[0].Producto != "Diferencia de cambio" {
		t.Fatalf("checkout cargo missing from dashboard: %+v", data.Sales)
	}
	if data.ChangeCount != 1 || len(data.Changes) != 1 || data.Timeline[0].Cambios != 1 {
		t.Fatalf("checkout change missing from dashboard: count=%d rows=%d timeline=%+v", data.ChangeCount, len(data.Changes), data.Timeline)
	}
	if data.Changes[0].SalienteCantidad != 1 || data.Changes[0].EntranteCantidad != 2 {
		t.Fatalf("unexpected dashboard change quantities: %+v", data.Changes[0])
	}
}

func TestCancelCargoKeepsInventoryUntouched(t *testing.T) {
	db := setupCambioInventoryDB(t)
	userID := seedCheckoutUser(t, db, "checkout-cancel-cargo")
	if _, err := addCheckoutSaleItem(db, userID, checkoutSaleInput{Tipo: "cargo", TotalCOP: 1800}); err != nil {
		t.Fatalf("add cancellation cargo: %v", err)
	}
	checkout, _, _, err := loadActiveCheckout(db, userID)
	if err != nil {
		t.Fatalf("load cancellation checkout: %v", err)
	}
	if _, err := processCheckout(db, userID, checkout.ID, "Cliente cargo", "Efectivo", "", &User{ID: userID, Username: "checkout-cancel-cargo"}); err != nil {
		t.Fatalf("process cancellation cargo: %v", err)
	}
	var saleID int
	if err := db.QueryRow(`SELECT id FROM ventas WHERE checkout_id = ?`, checkout.ID).Scan(&saleID); err != nil {
		t.Fatalf("query cancellation cargo: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin cargo cancellation: %v", err)
	}
	if err := cancelSale(tx, saleID, &User{ID: userID, Username: "checkout-cancel-cargo"}, "corrección"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("cancel cargo: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit cargo cancellation: %v", err)
	}
	var state string
	if err := db.QueryRow(`SELECT estado FROM ventas WHERE id = ?`, saleID).Scan(&state); err != nil {
		t.Fatalf("query cancelled cargo state: %v", err)
	}
	if state != "anulada" {
		t.Fatalf("expected cargo to be cancelled, got %s", state)
	}
}

func TestCheckoutTemplateRenders(t *testing.T) {
	tmpl, err := template.ParseFiles("templates/carrito.html", "templates/partials/header.html")
	if err != nil {
		t.Fatalf("parse checkout templates: %v", err)
	}
	var output bytes.Buffer
	data := checkoutPageData{
		Title:          "Carrito",
		Checkout:       checkoutOperation{Estado: checkoutStateDraft},
		Products:       []productOption{{ID: "P-001", Name: "Producto", SalePrice: 1000}},
		StockByProduct: map[string]int{"P-001": 2},
		PaymentMethods: []string{"Efectivo"},
		CurrentUser:    &User{Username: "tester", Role: "empleado", CSRFToken: "csrf"},
	}
	if err := tmpl.ExecuteTemplate(&output, "carrito.html", data); err != nil {
		t.Fatalf("render checkout template: %v", err)
	}
	if output.Len() == 0 {
		t.Fatal("expected rendered checkout template")
	}
}

func TestCheckoutMigrationUpgradesLegacySalesSchema(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`
		PRAGMA foreign_keys=ON;
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
		CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE);
		CREATE TABLE ventas (id INTEGER PRIMARY KEY AUTOINCREMENT, producto_id TEXT NOT NULL, cantidad INTEGER NOT NULL, precio_final REAL NOT NULL, metodo_pago TEXT NOT NULL, notas TEXT NOT NULL DEFAULT '', fecha TEXT NOT NULL);
		INSERT INTO users (username) VALUES ('legacy-user');
		INSERT INTO ventas (producto_id, cantidad, precio_final, metodo_pago, fecha) VALUES ('P-LEGACY', 1, 100, 'Efectivo', '2026-08-07T12:00:00Z');
		INSERT INTO schema_migrations (version, applied_at) VALUES
			(1, '2026-08-07T12:00:00Z'), (2, '2026-08-07T12:00:00Z'),
			(3, '2026-08-07T12:00:00Z'), (4, '2026-08-07T12:00:00Z'),
			(5, '2026-08-07T12:00:00Z'), (6, '2026-08-07T12:00:00Z')`)
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := applySchemaMigration(db, 7, migrateCheckoutSchema); err != nil {
		t.Fatalf("apply checkout migration: %v", err)
	}
	var columns int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('ventas') WHERE name IN ('tipo', 'producto_nombre', 'checkout_id')`).Scan(&columns); err != nil {
		t.Fatalf("check migrated sales columns: %v", err)
	}
	if columns != 3 {
		t.Fatalf("expected checkout sales columns, got %d", columns)
	}
	var legacyCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ventas WHERE producto_id = 'P-LEGACY'`).Scan(&legacyCount); err != nil {
		t.Fatalf("check legacy sale: %v", err)
	}
	if legacyCount != 1 {
		t.Fatalf("legacy sale was not preserved")
	}
	for _, table := range []string{"checkout_operaciones", "checkout_venta_items", "checkout_cambio_items"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
			t.Fatalf("check migrated table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("expected migrated table %s", table)
		}
	}
}

func setupProductDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		t.Fatalf("pragma wal: %v", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		t.Fatalf("pragma busy_timeout: %v", err)
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		db.Close()
		t.Fatalf("pragma synchronous: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE productos (
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
		CREATE TABLE unidades (
			id TEXT PRIMARY KEY,
			producto_id TEXT NOT NULL,
			estado TEXT NOT NULL,
			creado_en TEXT NOT NULL,
			caducidad TEXT
		);
	`)
	if err != nil {
		db.Close()
		t.Fatalf("create schema: %v", err)
	}
	return db
}

func TestGenerateNextProductSKUWithDB(t *testing.T) {
	db := setupProductDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO productos (sku, id, linea, nombre) VALUES ('P-001','P-001','L1','Prod1'),('P-002','P-002','L1','Prod2')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sku, err := generateNextProductSKU(db)
	if err != nil {
		t.Fatalf("generate sku db: %v", err)
	}
	if sku != "P-003" {
		t.Fatalf("expected P-003, got %q", sku)
	}
}

func TestGenerateNextProductSKUWithinTx(t *testing.T) {
	db := setupProductDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO productos (sku, id, linea, nombre) VALUES ('P-001','P-001','L1','Prod1'),('P-010','P-010','L1','Prod10')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	sku, err := generateNextProductSKU(tx)
	if err != nil {
		t.Fatalf("generate sku tx: %v", err)
	}
	if sku != "P-011" {
		t.Fatalf("expected P-011, got %q", sku)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestCreateProductNoDeadlock(t *testing.T) {
	db := setupProductDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO productos (sku, id, linea, nombre, precio_venta) VALUES ('P-001','P-001','Nutricion','Prod1', 1000)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			done <- fmt.Errorf("begin: %w", err)
			return
		}
		defer tx.Rollback()

		sku, err := generateNextProductSKU(tx)
		if err != nil {
			done <- fmt.Errorf("generate: %w", err)
			return
		}
		now := time.Now().Format(time.RFC3339)
		if err := upsertProducto(tx, sku, "Nuevo Producto", "Linea Test", now); err != nil {
			done <- fmt.Errorf("upsert: %w", err)
			return
		}
		if _, err := tx.ExecContext(ctx, `UPDATE productos SET precio_venta = ?, precio_venta_cop = ? WHERE sku = ?`, float64(2500), 2500, sku); err != nil {
			done <- fmt.Errorf("update precio: %w", err)
			return
		}
		for j := 0; j < 3; j++ {
			unitID := fmt.Sprintf("U-%s-%d", sku, time.Now().UnixNano()+int64(j))
			if _, err := tx.ExecContext(ctx, `INSERT INTO unidades (id, producto_id, estado, creado_en, caducidad) VALUES (?, ?, ?, ?, ?)`, unitID, sku, "Disponible", now, nil); err != nil {
				done <- fmt.Errorf("insert unidad: %w", err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			done <- fmt.Errorf("commit: %w", err)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transaction failed: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("deadlock detected while creating a product")
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM productos WHERE sku = 'P-002'`).Scan(&count); err != nil {
		t.Fatalf("query product: %v", err)
	}
	if count != 1 {
		t.Fatalf("product P-002 was not created, count=%d", count)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM unidades WHERE producto_id = 'P-002'`).Scan(&count); err != nil {
		t.Fatalf("query units: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 units, got %d", count)
	}
}

func TestGenerateNextProductSKUFindsGap(t *testing.T) {
	db := setupProductDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO productos (sku, id, linea, nombre) VALUES ('P-001','P-001','L1','A'),('P-002','P-002','L1','B'),('P-004','P-004','L1','C')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sku, err := generateNextProductSKU(db)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if sku != "P-005" {
		t.Fatalf("expected P-005 (max+1), got %q", sku)
	}
}
