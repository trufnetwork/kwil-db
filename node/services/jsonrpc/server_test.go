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
		{"json number 0", json.Number("0"), true},
		{"json number 0.0", json.Number("0.0"), true},
		{"json number 1", json.Number("1"), false},
		{"json number beyond float64", json.Number("1e400"), false},
		{"json number below float64", json.Number("1e-400"), false},
		{"json number 10", json.Number("10"), false},
		{"json number -0.0e5", json.Number("-0.0e5"), true},
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

	// ...with our jsonrpc.Error.Code
	var resp jsonrpc.Response
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, resp.Error.Code, jsonrpc.ErrorTimeout)
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

func Test_requestIDRoundTrip(t *testing.T) {
	srv, err := NewServer("127.0.0.1:", log.DiscardLogger)
	require.NoError(t, err)
	srv.RegisterMethodHandler(
		"rpc.dummy",
		MakeMethodHandler(func(context.Context, *any) (*json.RawMessage, *jsonrpc.Error) {
			respjson := []byte(`"hi"`)
			return (*json.RawMessage)(&respjson), nil
		}),
	)

	post := func(t *testing.T, body string) (int, map[string]json.RawMessage) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, pathRPCV1, strings.NewReader(body))
		w := httptest.NewRecorder()
		srv.srv.Handler.ServeHTTP(w, r)
		var resp map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return w.Code, resp
	}

	// The response carries the id exactly as the request did, whether the
	// method runs or fails: a fraction, an integer a float64 cannot hold,
	// one beyond int64, numbers too large or too small even for a float64,
	// and ids the spec does not allow but the server has always answered.
	for _, id := range []string{
		`1`, `-5`, `0.5`, `1.5`, `1e2`, `9007199254740993`,
		`9223372036854775807`, `9223372036854775808`, `-9223372036854775809`,
		`1e20`, `1e400`, `1e-400`, `-1e-400`, `"abc"`, `"1"`,
		`true`, `{}`, `[1]`, `[1e2]`, `{"a":9007199254740993}`, `{"z":1e2,"a":2}`,
	} {
		code, resp := post(t, `{"jsonrpc":"2.0","id":`+id+`,"method":"rpc.dummy"}`)
		require.Equal(t, http.StatusOK, code, id)
		require.Equal(t, id, string(resp["id"]), id)
		require.Equal(t, `"hi"`, string(resp["result"]), id)

		code, resp = post(t, `{"jsonrpc":"2.0","id":`+id+`,"method":"rpc.nope"}`)
		require.Equal(t, http.StatusNotFound, code, id)
		require.Equal(t, id, string(resp["id"]), id)
	}

	// An id of 0 or an empty string is still refused, however it is written.
	for _, id := range []string{`0`, `0.0`, `0e5`, `-0`, `-0.0`, `-0e5`, `""`} {
		code, resp := post(t, `{"jsonrpc":"2.0","id":`+id+`,"method":"rpc.dummy"}`)
		require.Equal(t, http.StatusBadRequest, code, id)
		require.JSONEq(t, `{"code":-32600,"message":"invalid json-rpc request object"}`, string(resp["error"]), id)
	}

	// Whitespace after the request object is fine, as it was. Anything else
	// after it is still refused.
	for _, extra := range []string{"\n", "\r\n", " \t\r\n "} {
		code, resp := post(t, `{"jsonrpc":"2.0","id":1,"method":"rpc.dummy"}`+extra)
		require.Equal(t, http.StatusOK, code, extra)
		require.Equal(t, `1`, string(resp["id"]), extra)
	}
	for _, extra := range []string{` x`, `}`, ` {}`, ` 1`} {
		code, resp := post(t, `{"jsonrpc":"2.0","id":1,"method":"rpc.dummy"}`+extra)
		require.Equal(t, http.StatusBadRequest, code, extra)
		require.JSONEq(t, `{"code":-32700,"message":"invalid request"}`, string(resp["error"]), extra)
	}
}
