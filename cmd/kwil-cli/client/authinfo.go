package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
)

const (
	kgwAuthTokenFileName = "auth.json"
)

// KGWAuthTokenFilePath returns the path to the file that stores the Gateway Authn cookies.
func KGWAuthTokenFilePath() string {
	return filepath.Join(config.ConfigDir(), kgwAuthTokenFileName)
}

// cookie is a copy of http.Cookie struct, with explicit json tags
type cookie struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`

	Path       string    `json:"path,omitempty"`        // optional
	Domain     string    `json:"domain,omitempty"`      // optional
	Expires    time.Time `json:"expires,omitempty"`     // optional
	RawExpires string    `json:"raw_expires,omitempty"` // for reading cookies only

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int      `json:"max_age,omitempty"`
	Secure   bool     `json:"secure,omitempty"`
	HttpOnly bool     `json:"http_only,omitempty"`
	SameSite int      `json:"same_site,omitempty"`
	Raw      string   `json:"raw,omitempty"`
	Unparsed []string `json:"unparsed,omitempty"` // Raw text of unparsed attribute-value pairs
}

func convertToCookie(c *http.Cookie) cookie {
	return cookie{
		Name:       c.Name,
		Value:      c.Value,
		Path:       c.Path,
		Domain:     c.Domain,
		Expires:    c.Expires,
		RawExpires: c.RawExpires,
		MaxAge:     c.MaxAge,
		Secure:     c.Secure,
		HttpOnly:   c.HttpOnly,
		SameSite:   int(c.SameSite),
		Raw:        c.Raw,
		Unparsed:   c.Unparsed,
	}
}

func convertToHttpCookie(c cookie) *http.Cookie {
	return &http.Cookie{
		Name:       c.Name,
		Value:      c.Value,
		Path:       c.Path,
		Domain:     c.Domain,
		Expires:    c.Expires,
		RawExpires: c.RawExpires,
		MaxAge:     c.MaxAge,
		Secure:     c.Secure,
		HttpOnly:   c.HttpOnly,
		SameSite:   http.SameSite(c.SameSite),
		Raw:        c.Raw,
		Unparsed:   c.Unparsed,
	}
}

// PersistedCookies is a set of Gateway Authn cookies that can be saved to a file.
// getDomain returns the domain of the URL.
func getDomain(target string) (string, error) {
	if target == "" {
		return "", errors.New("target is empty")
	}

	if !(strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")) {
		return "", errors.New("target missing scheme")
	}

	parsedTarget, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse target: %w", err)
	}

	return parsedTarget.Scheme + "://" + parsedTarget.Host, nil
}

// getCookieIdentifier returns a unique identifier for a cookie, base64 encoded.
func getCookieIdentifier(domain string, userIdentifier []byte) string {
	return base64.StdEncoding.EncodeToString(
		append([]byte(domain+"_"), userIdentifier...))
}

// PersistedCookies is a set of Gateway Auth cookies that can be saved to a file.
// It maps a base64 user identifier to a cookie, ensuring only one cookie per wallet.
// It uses a custom cookie type that is json serializable.
type PersistedCookies map[string]cookie

// LoadPersistedCookie loads a persisted cookie from the authn file.
// It will look up the cookie for the given user identifier.
// If nothing is found, it returns nil, nil.
func LoadPersistedCookie(authFile string, domain string, userIdentifier []byte) (*http.Cookie, error) {
	if _, err := os.Stat(authFile); os.IsNotExist(err) {
		return nil, nil
	}

	file, err := helpers.CreateOrOpenFile(authFile)
	if err != nil {
		return nil, fmt.Errorf("open kgw authn file: %w", err)
	}

	var aInfo PersistedCookies
	err = json.NewDecoder(file).Decode(&aInfo)
	if err != nil {
		return nil, fmt.Errorf("unmarshal kgw authn file: %w", err)
	}

	b64Identifier := getCookieIdentifier(domain, userIdentifier)
	cookie := aInfo[b64Identifier]

	return convertToHttpCookie(cookie), nil
}

// SaveCookie saves the cookie to authn file.
// It will overwrite the cookie if the address already exists.
func SaveCookie(authFile string, domain string, userIdentifier []byte, originCookie *http.Cookie) error {
	b64Identifier := getCookieIdentifier(domain, userIdentifier)
	cookie := convertToCookie(originCookie)

	authInfoBytes, err := helpers.ReadOrCreateFile(authFile)
	if err != nil {
		return fmt.Errorf("read kgw authn file: %w", err)
	}

	var aInfo PersistedCookies
	if len(authInfoBytes) == 0 {
		aInfo = make(PersistedCookies)
	} else {
		err = json.Unmarshal(authInfoBytes, &aInfo)
		if err != nil {
			return fmt.Errorf("unmarshal kgw authn file: %w", err)
		}
	}
	aInfo[b64Identifier] = cookie

	jsonBytes, err := json.MarshalIndent(&aInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal kgw authn info: %w", err)
	}

	err = os.WriteFile(authFile, jsonBytes, 0600)
	if err != nil {
		return fmt.Errorf("write kgw authn file: %w", err)
	}
	return nil
}

// DeleteCookie will delete a cookie that exists for a given user identifier.
// If no cookie exists for the user identifier, it will do nothing.
func DeleteCookie(authFile string, domain string, userIdentifier []byte) error {
	authInfoBytes, err := helpers.ReadOrCreateFile(authFile)
	if err != nil {
		return fmt.Errorf("read kgw authn file: %w", err)
	}

	var aInfo PersistedCookies
	if len(authInfoBytes) == 0 {
		aInfo = make(PersistedCookies)
	} else {
		err = json.Unmarshal(authInfoBytes, &aInfo)
		if err != nil {
			return fmt.Errorf("unmarshal kgw authn file: %w", err)
		}
	}

	b64Identifier := getCookieIdentifier(domain, userIdentifier)
	delete(aInfo, b64Identifier)

	jsonBytes, err := json.MarshalIndent(&aInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal kgw authn info: %w", err)
	}

	err = os.WriteFile(authFile, jsonBytes, 0644)
	if err != nil {
		return fmt.Errorf("write kgw authn file: %w", err)
	}
	return nil
}
