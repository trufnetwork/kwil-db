package url_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufnetwork/kwil-db/node/utils/url"
)

func TestParseURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    *url.URL
		wantErr error
	}{
		{
			name: "http",
			url:  "http://localhost:8080",
			want: &url.URL{
				Original: "http://localhost:8080",
				Scheme:   url.HTTP,
				Target:   "localhost:8080",
				Port:     8080,
			},
		},
		{
			name: "https, no port",
			url:  "https://localhost",
			want: &url.URL{
				Original: "https://localhost",
				Scheme:   url.HTTPS,
				Target:   "localhost",
			},
		},
		{
			name: "tcp",
			url:  "tcp://localhost:8080",
			want: &url.URL{
				Original: "tcp://localhost:8080",
				Scheme:   url.TCP,
				Target:   "localhost:8080",
				Port:     8080,
			},
		},
		{
			name: "no scheme",
			url:  "localhost:8080",
			want: &url.URL{
				Original: "localhost:8080",
				Scheme:   url.TCP,
				Target:   "localhost:8080",
				Port:     8080,
			},
		},
		{
			name: "no scheme (IP)",
			url:  "127.0.0.1:8080",
			want: &url.URL{
				Original: "127.0.0.1:8080",
				Scheme:   url.TCP,
				Target:   "127.0.0.1:8080",
				Port:     8080,
			},
		},
		{
			name: "no scheme or port (IP)",
			url:  "127.0.0.1",
			want: &url.URL{
				Original: "127.0.0.1",
				Scheme:   url.TCP,
				Target:   "127.0.0.1",
				Port:     0,
			},
		},
		{
			name: "no scheme or port",
			url:  "localhost",
			want: &url.URL{
				Original: "localhost",
				Scheme:   url.TCP,
				Target:   "localhost",
				Port:     0,
			},
		},
		{
			name: "no scheme",
			url:  "localhost:8080",
			want: &url.URL{
				Original: "localhost:8080",
				Scheme:   url.TCP,
				Target:   "localhost:8080",
				Port:     8080,
			},
		},
		{
			name: "IPv6 with scheme",
			url:  "tcp://[d4:93::1]:22",
			want: &url.URL{
				Original: "tcp://[d4:93::1]:22",
				Scheme:   url.TCP,
				Target:   "[d4:93::1]:22",
				Port:     22,
			},
		},
		{
			name:    "unknown scheme",
			url:     "foo://localhost:8080",
			wantErr: url.ErrUnknownScheme,
		},
		{
			name: "not localhost",
			url:  "tcp://0.0.0.0:50151",
			want: &url.URL{
				Original: "tcp://0.0.0.0:50151",
				Scheme:   url.TCP,
				Target:   "0.0.0.0:50151",
				Port:     50151,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := url.ParseURL(tt.url)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ParseURL() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.EqualExportedValues(t, *got, *tt.want)
		})
	}
}
