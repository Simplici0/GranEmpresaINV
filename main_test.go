package main

import (
	"database/sql"
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
