// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl055 struct{}

var GL055 = &gl055{}

func (r *gl055) ID() string { return "GL055" }

// isContainerSocketPath reports whether a DOCKER_HOST value points at a host
// container engine socket: the Docker socket under /var/run or /run (on
// current distributions /var/run is a symlink to /run, so both spell the same
// socket), or the Podman socket under /run, including per user runtime
// directories (/run/user/<uid>/podman/podman.sock) and values that expand
// $XDG_RUNTIME_DIR, which resolves under /run/user/<uid>.
func isContainerSocketPath(v string) bool {
	return strings.HasSuffix(v, "/docker.sock") || strings.HasSuffix(v, "/podman/podman.sock")
}

func (r *gl055) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		if f := checkDockerSocketVars(vars, file, job); f != nil {
			findings = append(findings, *f)
		}
	})

	return findings
}

// checkDockerSocketVars flags a DOCKER_HOST variable pointing at a host
// container engine socket. The socket itself is mounted via runner
// config.toml, not .gitlab-ci.yml, so the DOCKER_HOST reference is the
// statically detectable signal that a job is wired to control the host daemon.
// This rule owns DOCKER_HOST references only; a socket bind mount in a script
// is GL060's job, so one socket reference yields one finding, not two.
func checkDockerSocketVars(node *yaml.Node, file, job string) *finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := resolveScalar(node.Content[i+1])
		if key.Value != "DOCKER_HOST" || val == nil || !isContainerSocketPath(val.Value) {
			continue
		}
		return &finding.Finding{
			RuleID:   "GL055",
			Severity: finding.Warn,
			Job:      job,
			Message:  "DOCKER_HOST points at a host container socket (" + val.Value + ") — the job can control the runner's container daemon (container escape, access to other jobs' secrets); use TLS-based docker:dind (tcp://docker:2376) instead",
			File:     file, Line: key.Line, Col: key.Column,
		}
	}
	return nil
}
