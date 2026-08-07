package main

import (
	"context"
	"database/sql"
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

func TestSelectAndMarkSpecificUnitsPreservesSelection(t *testing.T) {
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
	ids, err := selectAndMarkSpecificUnits(tx, "P-003", []string{"U-022", "U-020"}, "Cambio")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("selectAndMarkSpecificUnits: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(ids) != 2 || ids[0] != "U-022" || ids[1] != "U-020" {
		t.Fatalf("selected ids changed order: %v", ids)
	}

	var selected, available int
	if err := db.QueryRow(`SELECT COUNT(*) FROM unidades WHERE producto_id = 'P-003' AND estado = 'Cambio'`).Scan(&selected); err != nil {
		t.Fatalf("count selected: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM unidades WHERE producto_id = 'P-003' AND estado = 'Disponible'`).Scan(&available); err != nil {
		t.Fatalf("count available: %v", err)
	}
	if selected != 2 || available != 1 {
		t.Fatalf("unexpected states selected=%d available=%d", selected, available)
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

	valid := httptest.NewRequest(http.MethodPost, "/venta", nil)
	valid.Header.Set("X-CSRF-Token", "csrf-token")
	valid = valid.WithContext(context.WithValue(valid.Context(), userContextKey, user))
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("expected valid token to pass, got %d", validResponse.Code)
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
	if migrationCount != 5 {
		t.Fatalf("expected schema migration version 5, got %d", migrationCount)
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
	data, err := buildDashboardSalesData(db, "2026-08-06", "2026-08-06", start, start)
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
