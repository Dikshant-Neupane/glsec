// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL038(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "sqlcmd -P with quoted literal to localhost without services — still flagged (#800)",
			yaml: `job:
  script:
    - sqlcmd -S localhost -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "sqlcmd -P with quoted literal to localhost with services — no finding (#800)",
			yaml: `job:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - sqlcmd -S localhost -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -h localhost with services from default — no finding (#800)",
			yaml: `default:
  services:
    - name: mysql:8.0
      alias: mysql
job:
  script:
    - mysql -h localhost -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "sqlcmd -P with quoted literal to external host",
			yaml: `job:
  script:
    - sqlcmd -S db.example.com -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mysqladmin ping to own service alias — no finding (#800)",
			yaml: `integration:mysql:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - mysqladmin ping -h mysql -uroot -pci-only --silent`,
			wantHits: 0,
		},
		{
			name: "sqlcmd to own service alias — no finding (#800)",
			yaml: `integration:mssql:
  services:
    - name: mcr.microsoft.com/mssql/server:2022-latest
      alias: mssql
  script:
    - sqlcmd -S mssql -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -h names another job's service, not this job's — still flagged",
			yaml: `integration:mysql:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - echo ok
integration:mssql:
  services:
    - name: mcr.microsoft.com/mssql/server:2022-latest
      alias: mssql
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mysql --host= names a service by image name, no alias — no finding",
			yaml: `job:
  services:
    - postgres:16
  script:
    - mysql --host=postgres -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "psql PGHOST names own service alias — no finding",
			yaml: `job:
  services:
    - name: postgres:16
      alias: pg
  script:
    - PGHOST=pg PGPASSWORD=ExampleP4ss! psql -U admin -c "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "psql to external host — still flagged",
			yaml: `job:
  script:
    - PGPASSWORD=ExampleP4ss! psql -h db.example.com -U admin -c "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mongosh --host names own service alias — no finding",
			yaml: `job:
  services:
    - name: mongo:7
      alias: mongo
  script:
    - mongosh --host mongo --username admin --password ExampleP4ss! mydb`,
			wantHits: 0,
		},
		{
			name: "mixed local and external hosts in one item — still flagged",
			yaml: `job:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1" && mysql -h db.example.com -u root -pOtherP4ss! -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "docker login literal is not suppressed by services",
			yaml: `job:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - docker login -u user -p ExampleP4ss! registry.example.com`,
			wantHits: 1,
		},
		{
			name: "service inherited through extends — no finding",
			yaml: `.db:
  services:
    - name: mysql:8.0
      alias: mysql
job:
  extends: .db
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "service from default — no finding",
			yaml: `default:
  services:
    - name: mysql:8.0
      alias: mysql
job:
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "127.0.0.1 target without services — still flagged",
			yaml: `job:
  script:
    - mysql -h 127.0.0.1 -u root -pci-only -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "127.0.0.1 target with services — no finding",
			yaml: `job:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - mysql -h 127.0.0.1 -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -h bare name of a namespaced service — still flagged (#800)",
			yaml: `job:
  services:
    - registry.example.com/team/mysql:8.0
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mysql -h double-underscore hostname of a namespaced service — no finding (#800)",
			yaml: `job:
  services:
    - registry.example.com/team/mysql:8.0
  script:
    - mysql -h registry.example.com__team__mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -h hyphen hostname of a namespaced service — no finding (#800)",
			yaml: `job:
  services:
    - registry.example.com/team/mysql:8.0
  script:
    - mysql -h registry.example.com-team-mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "sqlcmd -P with variable — safe",
			yaml: `job:
  script:
    - sqlcmd -S localhost -U SA -P "$MSSQL_PASSWORD" -Q "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -p with literal",
			yaml: `job:
  script:
    - mysql -u root -pExampleP4ss! -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mysql --password= with literal",
			yaml: `job:
  script:
    - mysqldump --password=ExampleP4ss! mydb > dump.sql`,
			wantHits: 1,
		},
		{
			name: "mysql --password= with variable — safe",
			yaml: `job:
  script:
    - mysql --password=$DB_PASSWORD -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "PGPASSWORD with literal",
			yaml: `job:
  script:
    - PGPASSWORD=ExampleP4ss! psql -U admin -c "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "PGPASSWORD with variable — safe",
			yaml: `job:
  script:
    - PGPASSWORD=$DB_PASSWORD psql -U admin -c "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mongosh --password with literal",
			yaml: `job:
  script:
    - mongosh --username admin --password ExampleP4ss! mydb`,
			wantHits: 1,
		},
		{
			name: "sed URL rewrite with hardcoded password",
			yaml: `job:
  script:
    - sed -i "s/sa:[^@]*@/sa:ExampleP4ss!@/" .env`,
			wantHits: 1,
		},
		{
			name: "sed URL rewrite with variable — safe",
			yaml: `job:
  script:
    - sed -i "s/sa:[^@]*@/sa:${DB_PASS}@/" .env`,
			wantHits: 0,
		},
		{
			name: "multiple violations in one job",
			yaml: `job:
  script:
    - sqlcmd -P "ExampleP4ss!" -Q "SELECT 1"
    - mysql -pExampleP4ss!`,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL038.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
