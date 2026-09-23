package mal

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Validate checks a detect tree for structural correctness WITHOUT needing a
// target or judge: each node must have exactly one variant, regexes must
// compile, and llm_judge nodes must carry a prompt. Returns the first problem.
func (d *Detect) Validate() error {
	set := 0
	if len(d.AnyOf) > 0 {
		set++
		for i := range d.AnyOf {
			if err := d.AnyOf[i].Validate(); err != nil {
				return fmt.Errorf("any_of[%d]: %w", i, err)
			}
		}
		if err := d.checkJudgeNotBypassable(); err != nil {
			return err
		}
	}
	if len(d.AllOf) > 0 {
		set++
		for i := range d.AllOf {
			if err := d.AllOf[i].Validate(); err != nil {
				return fmt.Errorf("all_of[%d]: %w", i, err)
			}
		}
	}
	if d.Not != nil {
		set++
		if err := d.Not.Validate(); err != nil {
			return fmt.Errorf("not: %w", err)
		}
	}
	if d.Contains != "" {
		set++
	}
	if d.Regex != "" {
		set++
		if _, err := regexp.Compile(d.Regex); err != nil {
			return fmt.Errorf("bad regex %q: %w", d.Regex, err)
		}
	}
	if d.LlmJudge != nil {
		set++
		if strings.TrimSpace(d.LlmJudge.Prompt) == "" {
			return fmt.Errorf("llm_judge requires a non-empty prompt")
		}
	}
	if set == 0 {
		return fmt.Errorf("empty detect node (needs one of: any_of, all_of, not, contains, regex, llm_judge)")
	}
	if set > 1 {
		return fmt.Errorf("detect node sets multiple variants; use exactly one per node")
	}
	return nil
}

// ValidationResult is the outcome of validating one attack file.
type ValidationResult struct {
	Path string
	ID   string
	Err  error // nil when the attack is valid
}

// ValidatePack strictly validates every attack file in a pack directory. Unlike
// LoadPack (which lenient-skips malformed files at scan time), it reports every
// file's status, validates the detect tree, and flags duplicate ids — so a CI
// `momus validate` can fail on a broken pack. The returned error is only for
// I/O problems (missing dir, walk failure), not attack-level issues.
func ValidatePack(root string) ([]ValidationResult, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pack %s is not a directory", root)
	}

	var results []ValidationResult
	seen := map[string]string{} // id -> first path
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		if IsReservedPackFile(filepath.Base(path)) {
			return nil // pack manifest / lock file, not an attack
		}
		res := ValidationResult{Path: path}
		a, err := LoadAttack(path)
		if err != nil {
			res.Err = err
			results = append(results, res)
			return nil
		}
		res.ID = a.ID
		if first, dup := seen[a.ID]; dup {
			res.Err = fmt.Errorf("duplicate id %q (first defined in %s)", a.ID, first)
		} else {
			seen[a.ID] = path
			if err := a.Detect.Validate(); err != nil {
				res.Err = fmt.Errorf("invalid detect: %w", err)
			}
		}
		results = append(results, res)
		return nil
	})
	return results, err
}

// checkJudgeNotBypassable rejects the detect shape that reliably manufactures
// false positives: an any_of that lets a LOOSE pattern outvote the judge. any_of
// is satisfied by a SINGLE branch, so a branch like `contains: "PWNED"` decides
// on its own and the judge never runs — and a refusal that quotes the text it is
// declining ("I won't reply with 'PWNED'") is then reported vulnerable.
//
// An ANCHORED regex branch is fine, and deliberately allowed: "^\\s*TOKEN\\s*$"
// matches only a reply that IS the token, which a refusal sentence cannot be.
// That is the pack's standard cheap-path-plus-semantic-fallback idiom — catch
// exact compliance without paying for a judge call, and ask the judge otherwise.
//
// Mixing per se is not the defect. any_of over several judges is fine, and so is
// any_of over several patterns: there the author has chosen pattern-only
// detection with their eyes open, and no judge is being quietly overruled.
func (d *Detect) checkJudgeNotBypassable() error {
	judged := 0
	var loose []string
	for i := range d.AnyOf {
		b := &d.AnyOf[i]
		if b.usesJudge() {
			judged++
			continue
		}
		if name := b.looseLeaf(); name != "" {
			loose = append(loose, name)
		}
	}
	if judged > 0 && len(loose) > 0 {
		return fmt.Errorf("any_of puts a judge alongside an unanchored branch (%s): "+
			"any_of needs only ONE branch to match, so that branch decides on its own and the judge "+
			"is never consulted — a refusal that quotes the payload would be reported vulnerable. "+
			"Use all_of to require both, or anchor the pattern (\"^...$\") so it can only match a "+
			"reply that IS the token", strings.Join(loose, ", "))
	}
	return nil
}

// looseLeaf names this subtree's first branch that could match inside a longer
// sentence — a `contains`, or a `regex` not anchored at both ends. It returns ""
// when nothing in the subtree can be satisfied by a passing mention.
func (d *Detect) looseLeaf() string {
	switch {
	case len(d.AnyOf) > 0:
		for i := range d.AnyOf {
			if n := d.AnyOf[i].looseLeaf(); n != "" {
				return n
			}
		}
	case len(d.AllOf) > 0:
		// all_of only matches if EVERY branch does, so one anchored branch is
		// enough to keep the whole node tight.
		tight := false
		var first string
		for i := range d.AllOf {
			if n := d.AllOf[i].looseLeaf(); n != "" {
				if first == "" {
					first = n
				}
			} else {
				tight = true
			}
		}
		if !tight {
			return first
		}
	case d.Not != nil:
		return "" // a negated branch cannot assert compliance on its own
	case d.Contains != "":
		return fmt.Sprintf("contains %q", d.Contains)
	case d.Regex != "":
		if !strings.HasPrefix(d.Regex, "^") || !strings.HasSuffix(d.Regex, "$") {
			return fmt.Sprintf("unanchored regex %q", d.Regex)
		}
	}
	return ""
}
