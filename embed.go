// Package momus embeds the core attack pack into the binary so a momus built
// with `go install` or fetched via npx / a release archive can scan out of the
// box, without needing packs/core present on disk.
package momus

import "embed"

// CorePack holds packs/core embedded at build time. Load it with
// mal.LoadPackFS(momus.CorePack, momus.CorePackRoot).
//
//go:embed packs/core
var CorePack embed.FS

// CorePackRoot is the path of the core pack within CorePack.
const CorePackRoot = "packs/core"
