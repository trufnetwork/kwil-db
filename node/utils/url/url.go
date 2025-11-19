// package url provides url functionalities to provide consistent
// parsing for Kwil clients.
package url

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// URL is a parsed URL.
type URL struct {
	// Original is the original URL string.
	Original string
	// Scheme is the protocol scheme, such as http or tcp.
	Scheme Scheme
	// Target is either the host, host:port, or unix socket path.
	Target string
	// Port is the port number, or 0 if not specified.
	Port int

	// the parsed url.URL. Not exported for test simplicity (comparing exported values).
	u *url.URL
}

// URL returns the parsed url.URL.
func (u *URL) URL() *url.URL {
	return u.u
}

// Scheme is a protocol scheme, such as http or tcp.
type Scheme string

func (s Scheme) Valid() bool {
	switch s {
	case HTTP, HTTPS, TCP, UNIX:
		return true
	default:
		return false
	}
}

func (s Scheme) String() string {
	return string(s)
}

const (
	HTTP  Scheme = "http"
	HTTPS Scheme = "https"
	TCP   Scheme = "tcp"
	UNIX  Scheme = "unix"
)

// ParseURL parses a URL string into a URL struct.
// URLs can be of the form:
// - http://localhost:8080
// - tcp://localhost:8080
// - localhost:8080
// - localhost
// - unix:///var/run/kwil.sock
// If the URL does not have a scheme, it is assumed to be a tcp address.
// If it does not have a port, it is set to 0. This is only appropriate for
// listen addresses.
func ParseURL(u string) (*URL, error) {
	return ParseURLWithDefaultScheme(u, "")
}

// ParseURLWithDefaultScheme is like ParseURL, but the default scheme may be
// specified. If empty, "tcp://" is used.
func ParseURLWithDefaultScheme(u, defaultScheme string) (*URL, error) {
	original := u
	// If the url does not have a scheme, give it one, rewrite and reparse.
	hasScheme, err := HasScheme(u)
	if err != nil {
		return nil, err
	}
	if !hasScheme {
		if defaultScheme == "" {
			defaultScheme = "tcp://"
		}
		u = defaultScheme + u
	}

	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	switch Scheme(parsed.Scheme) {
	case TCP, HTTP, HTTPS:
	case UNIX:
		target, err := expandPath(parsed.Path)
		if err != nil {
			return nil, err
		}
		parsed.Host = target
		parsed.Path = ""
		parsed.RawPath = ""
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownScheme, parsed.Scheme)
	}

	var port uint64
	if portString := parsed.Port(); portString != "" {
		port, err = strconv.ParseUint(portString, 10, 16)
		if err != nil {
			return nil, err
		}
	}

	return &URL{
		Original: original,
		Scheme:   Scheme(parsed.Scheme),
		Target:   parsed.Host,
		Port:     int(port),
		u:        parsed,
	}, nil
}

// HasScheme returns true if the url has a known scheme.
func HasScheme(u string) (bool, error) {
	parsed, err := url.Parse(u)
	if err != nil { // errors on 127.0.0.1:8080 so return false with no error
		return false, nil
	} // no error for localhost:8080, just empty parsed.Scheme string

	switch parsed.Scheme {
	case "tcp", "unix", "http", "https":
		return true, nil
	default:
		// see if it can be split by ://
		split := strings.Split(u, "://")
		if len(split) == 2 {
			return false, fmt.Errorf("%w: %s", ErrUnknownScheme, parsed.Scheme)
		}
		return false, nil
	}
}

func expandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return strings.Replace(path, "~", home, 1), nil
	}
	return path, nil
}
