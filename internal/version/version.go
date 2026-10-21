// Package version carries the tool's build metadata.
package version

// These values are overridable at build time with -ldflags, e.g.:
//
//	go build -ldflags "-X github.com/rom/qphpscanner/internal/version.Version=1.2.3"
var (
	// Name is the program name used in banners and reports.
	Name = "qphpscanner"

	// Version is the semantic version of the build.
	Version = "1.0.0"

	// Commit is the VCS revision the binary was built from (optional).
	Commit = "dev"

	// Date is the build date (optional).
	Date = "unknown"
)

// String returns a human readable version line.
func String() string {
	return Name + " " + Version + " (" + Commit + ", " + Date + ")"
}
