package version

import (
	"testing"

	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func Example_versionInfo_text() {
	display.Print(&respVersionInfo{
		Info: &versionInfo{
			Version:   "0.0.0",
			GitCommit: "00000000",

			BuildTime:  "0001-01-01T00:00:00Z",
			APIVersion: "0.0.0",
			GoVersion:  "unknown",
			Os:         "unknown",
			Arch:       "unknown",
		},
	}, nil, "text")
	//display.PrettyPrint(msg, "text")
	// Output:
	//  Version:	0.0.0
	//  Git commit:	00000000
	//  Built:	0001-01-01T00:00:00Z
	//  API version:	0.0.0
	//  Go version:	unknown
	//  OS/Arch:	unknown/unknown
}

func Example_versionInfo_json() {
	display.Print(&respVersionInfo{
		Info: &versionInfo{
			Version:    "0.0.0",
			GitCommit:  "00000000",
			BuildTime:  "0001-01-01T00:00:00Z",
			APIVersion: "0.0.0",
			GoVersion:  "unknown",
			Os:         "unknown",
			Arch:       "unknown",
		},
	}, nil, "json")
	// Output:
	// {
	//   "result": {
	//     "version": "0.0.0",
	//     "git_commit": "00000000",
	//     "build_time": "0001-01-01T00:00:00Z",
	//     "api_version": "0.0.0",
	//     "go_version": "unknown",
	//     "os": "unknown",
	//     "arch": "unknown"
	//   },
	//   "error": ""
	// }
}

func Test_versionInfo_marshalJSON(t *testing.T) {
	info := &respVersionInfo{
		Info: &versionInfo{
			Version:    "1.0.0",
			GitCommit:  "abcdef12",
			BuildTime:  "2023-01-01T12:00:00Z",
			APIVersion: "2.0.0",
			GoVersion:  "1.20",
			Os:         "linux",
			Arch:       "amd64",
		},
	}

	data, err := info.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"version":"1.0.0","git_commit":"abcdef12","build_time":"2023-01-01T12:00:00Z","api_version":"2.0.0","go_version":"1.20","os":"linux","arch":"amd64"}`
	if string(data) != wantJSON {
		t.Errorf("got %q, want %q", string(data), wantJSON)
	}
}

func Test_versionInfo_marshalText(t *testing.T) {
	info := &respVersionInfo{
		Info: &versionInfo{
			Version:    "1.0.0",
			GitCommit:  "abcdef12",
			BuildTime:  "2023-01-01T12:00:00Z",
			APIVersion: "2.0.0",
			GoVersion:  "1.20",
			Os:         "linux",
			Arch:       "amd64",
		},
	}

	data, err := info.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	wantText := `
 Version:	1.0.0
 Git commit:	abcdef12
 Built:		2023-01-01T12:00:00Z
 API version:	2.0.0
 Go version:	1.20
 OS/Arch:	linux/amd64`
	if string(data) != wantText {
		t.Errorf("got %q, want %q", string(data), wantText)
	}
}
