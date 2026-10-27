package store

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/comma-compliance/arc-relay/internal/safego"
)

type DB struct {
	*sql.DB
	path     string
	stopOnce sync.Once
	stopCh   chan struct{}
}

func Open(path string, migrationsFS fs.FS) (*DB, error) {
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_foreign_keys=ON&_busy_timeout=5000&_synchronous=NORMAL", path)
	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	// Refuse to start on a corrupt database - continuing writes makes recovery harder.
	var result string
	if err := sqlDB.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("database integrity check: %w", err)
	} else if result != "ok" {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("database integrity check failed: %s (recover with: sqlite3 db '.recover' | sqlite3 new.db)", result)
	}

	db := &DB{DB: sqlDB, path: path, stopCh: make(chan struct{})}
	if err := db.migrate(migrationsFS); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return db, nil
}

// StartBackup runs periodic backups using VACUUM INTO, keeping the two most
// recent copies alongside the live database. Safe to call once; a no-op if
// the path is empty (e.g. in-memory databases).
func (db *DB) StartBackup(interval time.Duration) {
	if db.path == "" || db.path == ":memory:" {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				safego.Run("db backup", db.runBackup)
			case <-db.stopCh:
				return
			}
		}
	}()
}

// StopBackup stops the periodic backup goroutine.
func (db *DB) StopBackup() {
	db.stopOnce.Do(func() { close(db.stopCh) })
}

// Close checkpoints the WAL and then closes the database.
func (db *DB) Close() error {
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		slog.Warn("wal checkpoint error", "err", err)
	}
	return db.DB.Close()
}

func (db *DB) runBackup() {
	dir := filepath.Dir(db.path)
	base := filepath.Base(db.path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	tmp := filepath.Join(dir, stem+".backup.tmp"+ext)
	cur := filepath.Join(dir, stem+".backup"+ext)
	prev := filepath.Join(dir, stem+".backup.prev"+ext)

	// Remove stale temp file from a previous interrupted backup, since VACUUM INTO
	// requires the destination not to exist.
	_ = os.Remove(tmp)

	// Write to temp file first so a failed backup doesn't discard the previous good copy.
	escaped := strings.ReplaceAll(tmp, "'", "''")
	if _, err := db.Exec(fmt.Sprintf(`VACUUM INTO '%s'`, escaped)); err != nil {
		slog.Warn("backup VACUUM INTO failed", "err", err)
		return
	}

	// Rotate only after the new backup succeeded.
	if _, err := os.Stat(cur); err == nil {
		if err := os.Rename(cur, prev); err != nil {
			slog.Warn("backup rotate failed", "err", err)
		}
	}
	if err := os.Rename(tmp, cur); err != nil {
		slog.Warn("backup finalize failed", "err", err)
		return
	}
	slog.Info("backup saved", "path", cur)
}

func (db *DB) migrate(migrationsFS fs.FS) error {
	// Create migrations tracking table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, ".")
	if err != nil {
		return fmt.Errorf("reading migrations dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var applied int
		err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", name).Scan(&applied)
		if err != nil {
			return fmt.Errorf("checking migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}

		content, err := fs.ReadFile(migrationsFS, name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("beginning transaction for %s: %w", name, err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("executing migration %s: %w", name, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("recording migration %s: %w", name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %s: %w", name, err)
		}

		slog.Info("applied migration", "version", name)
	}

	return nil
}
