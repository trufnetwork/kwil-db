package rpcserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
)

func ptrTo[T any](x T) *T {
	return &x
}

func Test_zeroID(t *testing.T) {
	var i any = (*int)(nil) // i != nil, it's a non-nil interface with nil data
	tests := []struct {
		name string
		id   any
		want bool
	}{
		{"int 0", int(0), true},
		{"int64 0", int64(0), true},
		{"float64 0", float64(0), true},
		{"ptr to int 0", ptrTo(0), true},
		{"nil ptr", (*int)(nil), true},
		{"non-interface to nil", i, true},
		{"nil", nil, true},
		{"empty string", "", true},
		{"int 1`", int(1), false},
		{"float64 1.1", float64(1.1), false},
		{"ptr to int 1", ptrTo(1), false},
		{"string a", "a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := zeroID(tt.id); got != tt.want {
				t.Errorf("zeroID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_timeout(t *testing.T) {
	// This handler will simulate a request that exceeds the timeout.
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK) // if test passes, should not get this!
	})

	// Wrap that handler with a 500ms timeout.
	h = jsonRPCTimeoutHandler(h, 500*time.Millisecond, log.New(log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug)))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(w, r)

	// Expect http.TimeoutHandler to have responded...
	assert.Equal(t, http.StatusServiceUnavailable, w.Result().StatusCode)

	// ...with our jsonrpc.Error.Code, and a null id since the request's id
	// is not known here.
	var resp map[string]json.RawMessage
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	var rpcErr jsonrpc.Error
	require.NoError(t, json.Unmarshal(resp["error"], &rpcErr))
	assert.Equal(t, rpcErr.Code, jsonrpc.ErrorTimeout)
	assert.Equal(t, `null`, string(resp["id"]))
}

func Test_unreadableIDIsNull(t *testing.T) {
	srv, err := NewServer("127.0.0.1:", log.DiscardLogger)
	require.NoError(t, err)

	// A body that does not parse, a request with no id and one with a null
	// id: each error response carries "id": null, since JSON-RPC 2.0 requires
	// an id member in every response.
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":`,
		`{"jsonrpc":"2.0","method":"rpc.nope"}`,
		`{"jsonrpc":"2.0","id":null,"method":"rpc.nope"}`,
	} {
		r := httptest.NewRequest(http.MethodPost, pathRPCV1, strings.NewReader(body))
		w := httptest.NewRecorder()
		srv.srv.Handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code, body)

		var resp map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Equal(t, `null`, string(resp["id"]), body)
	}
}

func Test_options(t *testing.T) {
	logger := log.NewStdoutLogger()

	const testOrigin = "whoever"

	wantCorsHeaders := http.Header{
		"Access-Control-Allow-Credentials": {"true"},
		"Access-Control-Allow-Headers":     {strings.Join([]string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "Authorization", "ResponseType", "Range"}, ", ")},
		"Access-Control-Allow-Methods":     {strings.Join([]string{http.MethodGet, http.MethodPost, http.MethodOptions}, ", ")},
		"Access-Control-Allow-Origin":      {testOrigin},
	}

	for _, tt := range []struct {
		name         string
		path         string
		withcors     bool
		reqMeth      string
		expectStatus int
		reqBody      io.Reader
	}{
		// JSON-RPC endpoint
		{
			name:         "no cors, options req",
			path:         pathRPCV1,
			withcors:     false,
			reqMeth:      http.MethodOptions,
			expectStatus: http.StatusMethodNotAllowed,
		},
		{
			name:         "with cors, options req",
			path:         pathRPCV1,
			withcors:     true,
			reqMeth:      http.MethodOptions,
			expectStatus: http.StatusOK,
		},
		{
			name:         "no cors, get req",
			path:         pathRPCV1,
			withcors:     false,
			reqMeth:      http.MethodGet,
			expectStatus: http.StatusMethodNotAllowed,
		},
		{
			name:         "with cors, post empty req",
			path:         pathRPCV1,
			withcors:     true,
			reqMeth:      http.MethodPost,
			expectStatus: http.StatusBadRequest, // not a jsonrpc req => 400 status code
			reqBody:      nil,
		},
		{
			name:         "with cors, post json req no method",
			path:         pathRPCV1,
			withcors:     true,
			reqMeth:      http.MethodPost,
			expectStatus: http.StatusNotFound, // method not found => 404 status code
			reqBody:      strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"rpc.nope"}`),
		},
		{
			name:         "with cors, post json req valid method",
			path:         pathRPCV1,
			withcors:     true,
			reqMeth:      http.MethodPost,
			expectStatus: http.StatusOK, // method not found => 404 status code
			reqBody:      strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"rpc.dummy","params":null}`),
		},
		{
			name:         "with cors, post json req valid method (no params)",
			path:         pathRPCV1,
			withcors:     true,
			reqMeth:      http.MethodPost,
			expectStatus: http.StatusOK, // method not found => 404 status code
			reqBody:      strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"rpc.dummy"}`),
		},
		// REST endpoints
		{
			name:         "no cors, rest options req",
			path:         pathSpecV1,
			withcors:     false,
			reqMeth:      http.MethodOptions,
			expectStatus: http.StatusMethodNotAllowed,
		},
		{
			name:         "with cors, rest options req",
			path:         pathSpecV1,
			withcors:     true,
			reqMeth:      http.MethodOptions,
			expectStatus: http.StatusOK,
		},
		{
			name:         "with cors, rest get req",
			path:         pathSpecV1,
			withcors:     true,
			reqMeth:      http.MethodGet,
			expectStatus: http.StatusOK,
		},
		{
			name:         "with cors, rest health options req",
			path:         pathHealthV1,
			withcors:     true,
			reqMeth:      http.MethodOptions,
			expectStatus: http.StatusOK,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Opt{}
			if tt.withcors {
				opts = append(opts, WithCORS())
			}
			srv, err := NewServer("127.0.0.1:", logger, opts...)
			require.NoError(t, err)

			srv.RegisterMethodHandler(
				"rpc.dummy",
				MakeMethodHandler(func(context.Context, *any) (*json.RawMessage, *jsonrpc.Error) {
					respjson := []byte(`"hi"`)
					return (*json.RawMessage)(&respjson), nil
				}),
			)

			r := httptest.NewRequest(tt.reqMeth, tt.path, tt.reqBody)
			r.Header.Set("Origin", testOrigin)
			w := httptest.NewRecorder()
			srv.srv.Handler.ServeHTTP(w, r)

			assert.Equal(t, tt.expectStatus, w.Code)

			if tt.withcors && tt.expectStatus == http.StatusOK {
				// expect the cors headers fields
				rhdr := w.Result().Header
				for hk, hvs := range wantCorsHeaders {
					vs, have := rhdr[hk]
					if !have {
						t.Fatalf("missing cors header %v", hk)
					}
					if !slices.Equal(vs, hvs) {
						t.Errorf("different cors headers: got %v, want %v", vs, hvs)
					}
				}

			}
		})
	}
}
