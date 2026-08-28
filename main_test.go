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
	if migrationCount != 7 {
		t.Fatalf("expected schema migration version 7, got %d", migrationCount)
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
