package executor

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"

	parser "github.com/Cgboal/DomainParser"
)

func find(slice []int, val int) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}

	return -1, false
}

func uniqueNonEmptyElementsOf(s []string) []string {
	unique := make(map[string]bool, len(s))
	us := make([]string, len(unique))
	for _, elem := range s {
		if len(elem) != 0 {
			if !unique[elem] {
				us = append(us, elem)
				unique[elem] = true
			}
		}
	}

	return us

}

func apexDomain(domain string) string {
	extractor := parser.NewDomainParser()

	apex := extractor.GetDomain(domain) + "." + extractor.GetTld(domain)

	return apex
}

func isDomainChecked(db *sql.DB, domain string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM checked_domains WHERE domain = ?", domain).Scan(&count)
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	} else {
		err := insertDomain(db, domain)
		if err != nil {
			return false, err
		}
	}

	return count > 0, nil
}

func insertDomain(db *sql.DB, domain string) error {
	_, err := db.Exec("INSERT INTO checked_domains (domain) VALUES (?)", domain)
	return err
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func createOrOpenDB(dbName string) (*sql.DB, error) {
	if !fileExists(dbName) {
		// If not, create the database and the necessary tables
		db, err := sql.Open("sqlite3", dbName)
		if err != nil {
			return nil, err
		}

		// Create the checked_urls table if it doesn't exist
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS checked_domains (
				id INTEGER PRIMARY KEY,
				domain TEXT
			)
		`)
		if err != nil {
			return nil, err
		}
		db.Close()
	}

	// Open the SQLite database
	db, err := sql.Open("sqlite3", dbName)
	if err != nil {
		return nil, err
	}

	return db, nil
}
