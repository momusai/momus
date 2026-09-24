// Package buildinfo carries the build's version string to packages that need
// it but must not import main.
//
// It exists so the User-Agent Momus sends is the version that is actually
// running. That string was previously hardcoded in each adapter, which meant it
// silently drifted from the real version at the first release — and a
// User-Agent is exactly the kind of detail an operator uses to work out which
// build hit their endpoint, so a wrong one is worse than none.
package buildinfo

// Version is the running build's version. The release build stamps it via
// -ldflags "-X main.version=..." and main copies it here at startup, so there
// is one source of truth and one linker flag rather than two that can disagree.
var Version = "dev"

// UserAgent returns the User-Agent for outbound requests. component names the
// caller ("momus" for target adapters, "momus-judge" for judge calls) so an
// operator reading their logs can tell an attack request from a grading one.
func UserAgent(component string) string {
	return component + "/" + Version
}
