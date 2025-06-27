package version

import (
	"fmt"
	"runtime/debug"
	"strings"
	"time"
)

// The kwilVersion should adhere to the semantic versioning (SemVer) spec 2.0.0.
// The general format is MAJOR.MINOR.PATCH-PRERELEASE+BUILD_META where both the
// prerelease label and build metadata are optional. For example:
//
//   - 0.6.0-rc.1
//   - 0.6.0+release
//   - 0.6.1
//   - 0.6.2-alpha0+go1.21.nocgo
const kwilVersion = "0.10.1" // remove "-pre" for the tagged commit

// KwildVersion may be set at compile time by:
//
//	go build -ldflags "-s -w -X github.com/trufnetwork/kwil-db/version.KwilVersion=0.10.0+release"
var (
	KwilVersion string
	Build       = vcsInfo()
)

func init() {
	if KwilVersion == "" { // not set via ldflags
		KwilVersion = kwilVersion
		if Build != nil && Build.RevisionShort != "" {
			// Append VCS revision and workspace dirty flag.
			sep := "+" // start build metadata
			if strings.Contains(KwilVersion, "+") {
				sep = "." // append to existing build metadata
			}
			KwilVersion += sep + Build.RevisionShort
			if Build.Dirty {
				KwilVersion += ".dirty"
			}
		}
	}
}

type BuildInfo struct {
	GoVersion     string
	Revision      string
	RevisionShort string
	RevTime       time.Time
	Dirty         bool
}

func vcsInfo() *BuildInfo {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	buildInfo := &BuildInfo{GoVersion: bi.GoVersion}
	for _, bs := range bi.Settings {
		switch bs.Key {
		case "vcs.revision":
			buildInfo.Revision = bs.Value
		case "vcs.time":
			revtime, err := time.Parse(time.RFC3339, bs.Value)
			if err != nil {
				fmt.Printf("invalid vcs.time %v: %v", bs.Value, err)
				continue
			}
			buildInfo.RevTime = revtime
		case "vcs.modified":
			buildInfo.Dirty = bs.Value == "true"
		}
	}
	const revLen = 9
	buildInfo.RevisionShort = buildInfo.Revision[:min(revLen, len(buildInfo.Revision))]
	return buildInfo
}
