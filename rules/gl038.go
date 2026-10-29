// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl038 struct{}

var GL038 = &gl038{}

func (r *gl038) ID() string { return "GL038" }

type credCheck struct {
	tool string
	re   *regexp.Regexp
	msg  string
	// db reports whether the credential goes to a database CLI whose
	// target host can be a job service container or localhost. Only
	// those checks are suppressed for own-service targets (#800, part 1).
	db bool
}

var credChecks = []credCheck{
	{
		tool: "sqlcmd",
		re:   regexp.MustCompile(`\bsqlcmd\b.*-P\s+["']?[^$"'\s]`),
		msg:  "script passes hardcoded credential to sqlcmd via -P flag — use a masked CI variable instead",
		db:   true,
	},
	{
		tool: "mysql",
		re:   regexp.MustCompile(`\bmysql(?:dump|pump)?\b.*\s-p[A-Za-z0-9!@#%^&*()\[\]{}<>]`),
		msg:  "script passes hardcoded credential to mysql via -p flag — use a masked CI variable instead",
		db:   true,
	},
	{
		tool: "mysql",
		re:   regexp.MustCompile(`\bmysql(?:dump|pump)?\b.*--password=[^$'"\s]`),
		msg:  "script passes hardcoded credential to mysql via --password flag — use a masked CI variable instead",
		db:   true,
	},
	{
		tool: "psql/PGPASSWORD",
		re:   regexp.MustCompile(`PGPASSWORD=[^$'"\s]`),
		msg:  "script passes hardcoded credential via PGPASSWORD — use a masked CI variable instead",
		db:   true,
	},
	{
		tool: "mongosh",
		re:   regexp.MustCompile(`\bmongo(?:sh|dump|restore|import|export)?\b.*--password\s+[^$\s"']`),
		msg:  "script passes hardcoded credential via --password flag — use a masked CI variable instead",
		db:   true,
	},
	{
		// A literal after -p/--password; $VAR, "$VAR", \$VAR (in a heredoc
		// for a remote shell), --password-stdin and another flag are not.
		tool: "docker login",
		re:   regexp.MustCompile(`\b(?:docker|podman)\s+login\b[^;&|\n]*\s(?:-p|--password)(?:\s+|=)["']?[^$"'\s\\-]`),
		msg:  "script passes a hardcoded password to docker login — anyone who can read the repository can use it; store it in a masked CI/CD variable and pipe it to --password-stdin",
	},
	{
		tool: "sed",
		re:   regexp.MustCompile(`\bsed\b.+s/[^/]+/[^/:]*:[^$][^@]*@/`),
		msg:  "script rewrites URL with hardcoded password literal via sed — use a masked CI variable instead",
	},
}

func (r *gl038) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)
	aliases := jobServiceAliases(doc, in)
	// The result depends on the job (its services), so visit each job's
	// script blocks separately instead of deduplicating shared sequences.
	EachScriptBlockPerJob(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkHardcodedCredScript(node, file, job, aliases[job])...)
	})
	return findings
}

// jobServiceAliases maps each job name to the hostnames its service
// containers are reachable under: the explicit alias: of each service,
// plus the image name of a service without an alias (GitLab links such a
// service under its image name, e.g. mysql:8.0 is reachable as mysql).
// Services from the job's extends: chain and from default: are included.
func jobServiceAliases(doc *yaml.Node, in *Inheritance) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	mapping := parser.Unwrap(doc)
	var defServices *yaml.Node
	if def := parser.FindKey(mapping, "default"); def != nil {
		defServices = parser.FindKey(def, "services")
	}
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		hosts := map[string]bool{}
		for _, services := range in.Chain(job, "services") {
			collectServiceHosts(services, hosts)
		}
		if defServices != nil && inheritsDefault(job, "services") {
			collectServiceHosts(defServices, hosts)
		}
		out[name.Value] = hosts
	})
	return out
}

func collectServiceHosts(services *yaml.Node, hosts map[string]bool) {
	if services == nil || services.Kind != yaml.SequenceNode {
		return
	}
	for _, item := range services.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			for _, h := range imageHosts(item.Value) {
				hosts[h] = true
			}
		case yaml.MappingNode:
			if alias := parser.FindKey(item, "alias"); alias != nil && alias.Kind == yaml.ScalarNode {
				hosts[strings.ToLower(alias.Value)] = true
			}
			if name := parser.FindKey(item, "name"); name != nil && name.Kind == yaml.ScalarNode {
				for _, h := range imageHosts(name.Value) {
					hosts[h] = true
				}
			}
		}
	}
}

// imageHosts returns the hostnames an image reference can be reached under:
// the reference without tag or digest, and its last path component.
func imageHosts(ref string) []string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// Strip a tag, but only when it follows the last path component.
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
		ref = ref[:i]
	}
	ref = strings.ToLower(ref)
	hosts := []string{ref}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		hosts = append(hosts, ref[i+1:])
	}
	return hosts
}

// hostOptionRe extracts the host values named by database CLI host options
// in a script item: -h / --host (mysql, psql, mongosh), -S (sqlcmd) and
// PGHOST (psql). hostOptionAttachedRe covers the attached short forms
// (-hmysql, -Smssql).
var hostOptionRe = regexp.MustCompile(`(?:^|[\s;&|])(?:-h|-S|--host|PGHOST)(?:\s+|=)\s*["']?([^\s;&|"']+)`)
var hostOptionAttachedRe = regexp.MustCompile(`(?:^|[\s;&|])-[hS]["']?([^\s;&|"']+)`)

var localHosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
}

// targetsOwnService reports whether every host option in the script item
// names a service container of the job or a loopback host, and at least one
// host option is present. An item with no host option, or one that mixes a
// local host with an external host, is not suppressed: a credential with no
// explicit target, or one that also reaches an external host, stays flagged.
func targetsOwnService(item string, aliases map[string]bool) bool {
	matches := hostOptionRe.FindAllStringSubmatch(item, -1)
	matches = append(matches, hostOptionAttachedRe.FindAllStringSubmatch(item, -1)...)
	if len(matches) == 0 {
		return false
	}
	for _, m := range matches {
		if !localHosts[normalizeHost(m[1])] && !aliases[normalizeHost(m[1])] {
			return false
		}
	}
	return true
}

// normalizeHost strips a connection prefix (tcp:, np:), a port (host:port
// or host,port as sqlcmd uses) and an instance suffix (host\instance),
// and lowercases the result.
func normalizeHost(host string) string {
	host = strings.Trim(host, `"'`)
	host = strings.TrimPrefix(strings.ToLower(host), "tcp:")
	host = strings.TrimPrefix(host, "np:")
	host = strings.TrimPrefix(host, "lpc:")
	host = strings.Trim(host, "[]")
	if i := strings.Index(host, `\`); i >= 0 {
		host = host[:i]
	}
	if i := strings.Index(host, ","); i >= 0 {
		host = host[:i]
	}
	// A single colon separates a port; several colons mean an IPv6 address.
	if strings.Count(host, ":") == 1 {
		host = host[:strings.Index(host, ":")]
	}
	return host
}

func checkHardcodedCredScript(node *yaml.Node, file, job string, aliases map[string]bool) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		for _, check := range credChecks {
			if !check.re.MatchString(item.Value) {
				continue
			}
			if check.db && targetsOwnService(item.Value, aliases) {
				// The credential only reaches the job's own service
				// container or localhost: keep looking for another
				// (non-suppressed) check in the same item.
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL038",
				Severity: finding.Error,
				Job:      job,
				Message:  fmt.Sprintf("[%s] %s", check.tool, check.msg),
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
			break
		}
	}
	return findings
}
