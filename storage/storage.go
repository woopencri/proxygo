package storage

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Proxy struct {
	ID        int64
	Address   string // host:port
	Protocol  string // http, socks5
	Username  string
	Password  string
	FailCount int
	LastCheck time.Time
	CreatedAt time.Time
}

func (p Proxy) IdentityKey() string {
	return fmt.Sprintf("%s|%s|%s|%s", p.Protocol, p.Address, p.Username, p.Password)
}

type Storage struct {
	db *sql.DB
}

func New(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite 单写

	s := &Storage{db: db}
	if err := s.initSchema(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Storage) initSchema() error {
	exists, err := s.tableExists("proxies")
	if err != nil {
		return err
	}
	if !exists {
		return s.createSchema()
	}

	hasUsername, hasPassword, err := s.getProxyColumns()
	if err != nil {
		return err
	}
	identityIndexFound, addressUniqueFound, err := s.inspectProxyIndexes()
	if err != nil {
		return err
	}

	if !hasUsername || !hasPassword || addressUniqueFound {
		if err := s.migrateSchema(hasUsername && hasPassword); err != nil {
			return err
		}
		identityIndexFound = true
	}

	if !identityIndexFound {
		_, err = s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_identity ON proxies (protocol, address, username, password)`)
		return err
	}
	return nil
}

func (s *Storage) createSchema() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS proxies (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			address    TEXT NOT NULL,
			protocol   TEXT NOT NULL,
			username   TEXT NOT NULL DEFAULT '',
			password   TEXT NOT NULL DEFAULT '',
			fail_count INTEGER NOT NULL DEFAULT 0,
			last_check DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_identity ON proxies (protocol, address, username, password);
	`)
	return err
}

func (s *Storage) tableExists(name string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count)
	return count > 0, err
}

func (s *Storage) getProxyColumns() (bool, bool, error) {
	hasUsername := false
	hasPassword := false

	rows, err := s.db.Query(`PRAGMA table_info(proxies)`)
	if err != nil {
		return false, false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultValue, &pk); err != nil {
			return false, false, err
		}
		switch strings.ToLower(name) {
		case "username":
			hasUsername = true
		case "password":
			hasPassword = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, false, err
	}
	return hasUsername, hasPassword, nil
}

func (s *Storage) inspectProxyIndexes() (bool, bool, error) {
	indexRows, err := s.db.Query(`PRAGMA index_list(proxies)`)
	if err != nil {
		return false, false, err
	}
	defer indexRows.Close()

	identityIndexFound := false
	addressUniqueFound := false
	for indexRows.Next() {
		var seq int
		var name string
		var unique int
		var origin, partial string
		if err := indexRows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return false, false, err
		}
		if unique == 0 {
			continue
		}
		cols, err := s.indexColumns(name)
		if err != nil {
			return false, false, err
		}
		joined := strings.Join(cols, ",")
		if joined == "protocol,address,username,password" {
			identityIndexFound = true
		}
		if len(cols) == 1 && cols[0] == "address" {
			addressUniqueFound = true
		}
	}
	if err := indexRows.Err(); err != nil {
		return false, false, err
	}

	return identityIndexFound, addressUniqueFound, nil
}

func (s *Storage) indexColumns(indexName string) ([]string, error) {
	rows, err := s.db.Query(fmt.Sprintf(`PRAGMA index_info(%s)`, quoteSQLiteIdent(indexName)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var seqno, cid int
		var name string
		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			return nil, err
		}
		cols = append(cols, strings.ToLower(name))
	}
	return cols, rows.Err()
}

func quoteSQLiteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func (s *Storage) migrateSchema(hasCredentialColumns bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.Exec(`
		CREATE TABLE proxies_new (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			address    TEXT NOT NULL,
			protocol   TEXT NOT NULL,
			username   TEXT NOT NULL DEFAULT '',
			password   TEXT NOT NULL DEFAULT '',
			fail_count INTEGER NOT NULL DEFAULT 0,
			last_check DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("create temp schema: %w", err)
	}

	insertSQL := `
		INSERT OR IGNORE INTO proxies_new (id, address, protocol, username, password, fail_count, last_check, created_at)
		SELECT id, address, protocol, '', '', fail_count, last_check, created_at
		FROM proxies
	`
	if hasCredentialColumns {
		insertSQL = `
			INSERT OR IGNORE INTO proxies_new (id, address, protocol, username, password, fail_count, last_check, created_at)
			SELECT id, address, protocol, COALESCE(username, ''), COALESCE(password, ''), fail_count, last_check, created_at
			FROM proxies
		`
	}
	if _, err = tx.Exec(insertSQL); err != nil {
		return fmt.Errorf("copy schema data: %w", err)
	}
	if _, err = tx.Exec(`DROP TABLE proxies`); err != nil {
		return fmt.Errorf("drop old schema: %w", err)
	}
	if _, err = tx.Exec(`ALTER TABLE proxies_new RENAME TO proxies`); err != nil {
		return fmt.Errorf("rename schema: %w", err)
	}
	if _, err = tx.Exec(`CREATE UNIQUE INDEX idx_proxies_identity ON proxies (protocol, address, username, password)`); err != nil {
		return fmt.Errorf("create identity index: %w", err)
	}
	return tx.Commit()
}

// AddProxy 新增代理，已存在则忽略
func (s *Storage) AddProxy(address, protocol, username, password string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO proxies (address, protocol, username, password) VALUES (?, ?, ?, ?)`,
		address, protocol, username, password,
	)
	return err
}

// AddProxies 批量新增
func (s *Storage) AddProxies(proxies []Proxy) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO proxies (address, protocol, username, password) VALUES (?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, p := range proxies {
		if _, err := stmt.Exec(p.Address, p.Protocol, p.Username, p.Password); err != nil {
			log.Printf("insert proxy %s error: %v", p.Address, err)
		}
	}
	return tx.Commit()
}

// GetRandom 随机取一个可用代理
func (s *Storage) GetRandom() (*Proxy, error) {
	rows, err := s.db.Query(
		`SELECT id, address, protocol, username, password, fail_count, last_check, created_at
		 FROM proxies WHERE fail_count < 3
		 ORDER BY RANDOM() LIMIT 1`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		p := &Proxy{}
		var lastCheck sql.NullTime
		if err := rows.Scan(&p.ID, &p.Address, &p.Protocol, &p.Username, &p.Password, &p.FailCount, &lastCheck, &p.CreatedAt); err != nil {
			return nil, err
		}
		if lastCheck.Valid {
			p.LastCheck = lastCheck.Time
		}
		return p, nil
	}
	return nil, fmt.Errorf("no available proxy")
}

// GetAll 获取所有可用代理
func (s *Storage) GetAll() ([]Proxy, error) {
	rows, err := s.db.Query(
		`SELECT id, address, protocol, username, password, fail_count, last_check, created_at
		 FROM proxies WHERE fail_count < 3`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		p := Proxy{}
		var lastCheck sql.NullTime
		if err := rows.Scan(&p.ID, &p.Address, &p.Protocol, &p.Username, &p.Password, &p.FailCount, &lastCheck, &p.CreatedAt); err != nil {
			return nil, err
		}
		if lastCheck.Valid {
			p.LastCheck = lastCheck.Time
		}
		proxies = append(proxies, p)
	}
	return proxies, nil
}

// GetRandomExclude 排除指定代理身份后随机取一个
func (s *Storage) GetRandomExclude(excludes []string) (*Proxy, error) {
	proxies, err := s.GetAll()
	if err != nil {
		return nil, err
	}

	excludeMap := make(map[string]bool, len(excludes))
	for _, e := range excludes {
		excludeMap[e] = true
	}

	var available []Proxy
	for _, p := range proxies {
		if !excludeMap[p.IdentityKey()] {
			available = append(available, p)
		}
	}

	if len(available) == 0 {
		return s.GetRandom()
	}

	p := available[rand.Intn(len(available))]
	return &p, nil
}

// Delete 立即删除指定地址的代理（兼容旧调用）
func (s *Storage) Delete(address string) error {
	_, err := s.db.Exec(`DELETE FROM proxies WHERE address = ?`, address)
	return err
}

// DeleteByID 按 ID 删除代理
func (s *Storage) DeleteByID(id int64) error {
	_, err := s.db.Exec(`DELETE FROM proxies WHERE id = ?`, id)
	return err
}

// IncrFail 增加失败次数
func (s *Storage) IncrFail(address string) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET fail_count = fail_count + 1, last_check = CURRENT_TIMESTAMP WHERE address = ?`,
		address,
	)
	return err
}

// ResetFail 重置失败次数（验证通过）
func (s *Storage) ResetFail(address string) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET fail_count = 0, last_check = CURRENT_TIMESTAMP WHERE address = ?`,
		address,
	)
	return err
}

// DeleteInvalid 删除失败次数超过阈值的代理
func (s *Storage) DeleteInvalid(maxFailCount int) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM proxies WHERE fail_count >= ?`, maxFailCount)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Count 返回可用代理数量
func (s *Storage) Count() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE fail_count < 3`).Scan(&count)
	return count, err
}

// CountByProtocol 按协议统计数量
func (s *Storage) CountByProtocol(protocol string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE fail_count < 3 AND protocol = ?`, protocol).Scan(&count)
	return count, err
}

// GetByProtocol 按协议获取代理列表
func (s *Storage) GetByProtocol(protocol string) ([]Proxy, error) {
	rows, err := s.db.Query(
		`SELECT id, address, protocol, username, password, fail_count, last_check, created_at
		 FROM proxies WHERE fail_count < 3 AND protocol = ?
		 ORDER BY created_at DESC`, protocol,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		p := Proxy{}
		var lastCheck sql.NullTime
		if err := rows.Scan(&p.ID, &p.Address, &p.Protocol, &p.Username, &p.Password, &p.FailCount, &lastCheck, &p.CreatedAt); err != nil {
			return nil, err
		}
		if lastCheck.Valid {
			p.LastCheck = lastCheck.Time
		}
		proxies = append(proxies, p)
	}
	return proxies, nil
}

// Close 关闭数据库
func (s *Storage) Close() error {
	return s.db.Close()
}
