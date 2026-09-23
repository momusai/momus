// Package mal implements the Momus Attack Language: a YAML DSL for describing
// AI-security tests, plus loaders and a detector-tree evaluator.
package mal

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Severity is the impact rating of an attack finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Attack is a single MAL rule parsed from YAML.
type Attack struct {
	MalVersion  string   `yaml:"mal_version" json:"mal_version"`
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Category    string   `yaml:"category" json:"category"`
	Severity    Severity `yaml:"severity,omitempty" json:"severity"`
	OWASPLLM    string   `yaml:"owasp_llm,omitempty" json:"owasp_llm,omitempty"`
	MITREAtlas  []string `yaml:"mitre_atlas,omitempty" json:"mitre_atlas,omitempty"`
	References  []string `yaml:"references,omitempty" json:"references,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Payload     string   `yaml:"payload" json:"payload"`
	Detect      Detect   `yaml:"detect" json:"detect"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// Validate returns an error if the attack is not well-formed.
func (a *Attack) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("missing id")
	}
	if a.MalVersion == "" {
		return fmt.Errorf("%s: missing mal_version", a.ID)
	}
	if a.Payload == "" {
		return fmt.Errorf("%s: missing payload", a.ID)
	}
	switch a.Severity {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return fmt.Errorf("%s: invalid severity %q (want info|low|medium|high|critical)", a.ID, a.Severity)
	}
	// Validate the detect tree at load time too, so the SCAN path (LoadPack ->
	// LoadAttack -> Validate) rejects a structurally-broken detector instead of
	// silently reducing a multi-variant node to one first-precedence matcher —
	// which could drop an intended llm_judge gate and cause a false positive.
	if err := a.Detect.Validate(); err != nil {
		return fmt.Errorf("%s: invalid detect: %w", a.ID, err)
	}
	return nil
}

// LoadAttack parses a single MAL YAML file from disk.
func LoadAttack(path string) (*Attack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseAttack(data, path)
}

// ParseAttack parses MAL YAML bytes; source is used only for error messages.
// Used by both the on-disk loader and the embedded/fs.FS loader.
func ParseAttack(data []byte, source string) (*Attack, error) {
	var a Attack
	if err := yaml.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}
	if a.Severity == "" {
		a.Severity = SeverityMedium
	}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return &a, nil
}
