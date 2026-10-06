package rpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	"github.com/trufnetwork/kwil-db/node/metrics"
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/openrpc"
)

// The endpoint path is constant for now.
const (
	pathAPIV1       = "/api/v1" // REST API endpoints
	pathHealthV1    = pathAPIV1 + "/health"
	pathSvcHealthV1 = pathHealthV1 + "/{svc}"

	pathRPCV1  = "/rpc/v1"
	pathSpecV1 = "/spec/v1"
)

type contextRPCKey string

const (
	RequestIPCtx contextRPCKey = "clientIP"
	ServerCtx    contextRPCKey = "server"
)

// Server is a JSON-RPC server.
type Server struct {
	srv            *http.Server
	addr           string // the listener's actual address, not the config
	unix           bool   // the listener's network should be "unix" instead of "tcp"
	log            log.Logger
	methodHandlers map[jsonrpc.Method]MethodHandler
	methodDefs     map[string]*openrpc.MethodDefinition
	services       map[string]Svc
	specInfo       *openrpc.Info
	spec           json.RawMessage
	authSHA        []byte
	tlsCfg         *tls.Config
}

type serverConfig struct {
	pass       string
	tlsConfig  *tls.Config
	timeout    time.Duration
	enableCORS bool
	compress   bool
	specInfo   *openrpc.Info
	reqSzLimit int
	proxyCount int
}

type Opt func(*serverConfig)

// WithPass will require a password in the request header's Authorization value
// in "Basic" formatting. Don't use this without TLS; either terminate TLS in an
// upstream reverse proxy, or use WithTLS with Certificates provided.
func WithPass(pass string) Opt {
	return func(c *serverConfig) {
		c.pass = pass
	}
}

// WithTLS provides a tls.Config to use with tls.NewListener around the standard
// net.Listener.
func WithTLS(cfg *tls.Config) Opt {
	return func(c *serverConfig) {
		c.tlsConfig = cfg
	}
}

func WithTrustedProxyCount(trustedProxyCount int) Opt {
	return func(c *serverConfig) {
		c.proxyCount = trustedProxyCount
	}
}

// WithMetricsNamespace enables metrics with the provided namespace.
// func WithMetricsNamespace(namespace string) Opt {
// 	return func(c *serverConfig) {
// 		c.namespace = namespace
// 	}
// }

// WithServerInfo sets the OpenRPC "info" section to use when serving the
// OpenRPC JSON specification either via a spec REST endpoint or the
// rpc.discover JSON-RPC method.
func WithServerInfo(specInfo *openrpc.Info) Opt {
	return func(c *serverConfig) {
		c.specInfo = specInfo
	}
}

// WithReqSizeLimit sets the request size limit in bytes.
func WithReqSizeLimit(sz int) Opt {
	return func(c *serverConfig) {
		c.reqSzLimit = sz
	}
}

// WithTimeout specifies a timeout on all RPC requests that when exceeded will
// cancel the request.
func WithTimeout(timeout time.Duration) Opt {
	return func(c *serverConfig) {
		c.timeout = timeout
	}
}

// WithCORS adds CORS headers to response so browser will permit cross origin
// RPC requests.
func WithCORS() Opt {
	return func(c *serverConfig) {
		c.enableCORS = true
	}
}

// WithCompression enables gzip compression of responses. The adds some
// computational overhead, but may be useful if there is no reverse proxy to
// offload this work.
func WithCompression() Opt {
	return func(c *serverConfig) {
		c.compress = true
	}
}

// checkAddr cleans the address, and indicates if it is a unix socket (local
// filesystem path). The addr for NewServer should be a host:port style string,
// but if it is a URL, this will attempt to get the host and port from it.
func checkAddr(addr string) (string, bool, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			host = addr
			port = "8484"
		} else if strings.Contains(err.Error(), "too many colons in address") {
			u, err := url.Parse(addr)
			if err != nil {
				return "", false, err
			}
			host, port = u.Host, u.Port()
		} else {
			return "", false, err
		}
	}

	if strings.HasPrefix(host, "/") { // unix, no port
		return host, true, nil
	}

	return net.JoinHostPort(host, port), false, nil
}

const (
	// defaultWriteTimeout is the default WriteTimeout for the http.Server.
	defaultWriteTimeout = 45 * time.Second
	// 4 MiB + overhead request size limit
	defaultSzLimit = 1<<22 + 1<<14
)

var (
	defaultSpecInfo = &openrpc.Info{
		Title:       "Kwil DB RPC service",
		Description: `The JSON-RPC service for Kwil DB.`,
		License: &openrpc.License{ // the spec file's license
			Name: "CC0-1.0",
			URL:  "https://creativecommons.org/publicdomain/zero/1.0/legalcode",
		},
		Version: "0.1.0",
	}

	mets metrics.RPCMetrics = metrics.RPC
)

// NewServer creates a new JSON-RPC server. Use RegisterMethodHandler or
// RegisterSvc to add method handlers.
func NewServer(addr string, log log.Logger, opts ...Opt) (*Server, error) {
	addr, isUNIX, err := checkAddr(addr)
	if err != nil {
		return nil, err
	}
	if isUNIX { // prepare for the socket file
		err = os.MkdirAll(filepath.Dir(addr), 0700) // ensure parent dir exists
		if err != nil {
			return nil, fmt.Errorf("failed to create admin service unix socket directory at %q: %w",
				filepath.Dir(addr), err)
		}

		err = syscall.Unlink(addr) // if left from last run
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to build grpc server: %w", err)
		}
	}

	cfg := &serverConfig{
		timeout:    defaultWriteTimeout,
		specInfo:   defaultSpecInfo,
		reqSzLimit: defaultSzLimit,
		// default trusted proxy count is 0 (direct connect assumed)
	}
	for _, opt := range opts {
		opt(cfg)
	}

	mux := http.NewServeMux() // http.DefaultServeMux has the pprof endpoints mounted

	disconnectTimeout := cfg.timeout + 5*time.Second // for jsonRPCTimeoutHandler to respond, don't disconnect immediately
	srv := &http.Server{
		Addr:              addr, // only used with srv.ListenAndServe, not Serve
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,  // receiving request body should not take longer
		WriteTimeout:      disconnectTimeout, // full request handling: receive request, handle request, AND send response
	}

	if srv.ReadTimeout > srv.WriteTimeout {
		srv.ReadTimeout = srv.WriteTimeout
	}
	if srv.ReadHeaderTimeout > srv.ReadTimeout {
		srv.ReadHeaderTimeout = srv.ReadTimeout
	}

	s := &Server{
		srv:            srv,
		unix:           isUNIX,
		log:            log,
		methodHandlers: make(map[jsonrpc.Method]MethodHandler),
		methodDefs:     make(map[string]*openrpc.MethodDefinition),
		services:       make(map[string]Svc),
		specInfo:       cfg.specInfo,
		tlsCfg:         cfg.tlsConfig,
	}

	if cfg.pass != "" {
		authSHA := sha256.Sum256([]byte(cfg.pass))
		s.authSHA = slices.Clone(authSHA[:])
	} // otherwise no basic auth check

	// JSON-RPC handler (POST+OPTIONS)
	var h http.Handler
	h = http.HandlerFunc(s.handlerJSONRPCV1) // last, after middleware below
	h = http.MaxBytesHandler(h, int64(cfg.reqSzLimit))
	// h = middleware.Logger(h)
	h = middleware.Recoverer(h)
	// amazingly, exceeding the server's write timeout does not cancel request
	// contexts: https://github.com/golang/go/issues/59602
	// So, we add a timeout to the Request's context.
	h = jsonRPCTimeoutHandler(h, cfg.timeout, log)
	if cfg.enableCORS {
		h = corsHandler(h)
	}

	compMW := func(h http.Handler) http.Handler { return h }
	if cfg.compress {
		compMW = middleware.Compress(5)
	}
	h = compMW(h)
	h = realIPHandler(h, cfg.proxyCount) // for effective rate limiting

	// h = recoverer(h, log) // first, wrap with defer and call next ^

	mux.Handle(pathRPCV1, h) // do not add method! We need to handle OPTIONS for CORS, but only POST in JSON-RPC

	// NOTE: for challenges at server level (above JSON-RPC methods):
	// mux.Handle(pathRPCV1 + "/challenge", challengeHandler)

	// OpenRPC specification handler (GET)
	var specHandler http.Handler
	specHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		http.ServeContent(w, r, "openrpc.json", time.Time{}, bytes.NewReader(s.spec))
	})
	specHandler = compMW(specHandler)
	if cfg.enableCORS {
		specHandler = corsHandler(specHandler)
	}
	specHandler = recoverer(specHandler, log)
	mux.Handle(pathSpecV1, specHandler)

	// aggregate health endpoint handler
	var healthHandler http.Handler
	healthHandler = http.HandlerFunc(s.healthMethodHandler)
	if cfg.enableCORS {
		healthHandler = corsHandler(healthHandler)
	}
	healthHandler = compMW(healthHandler)
	healthHandler = recoverer(healthHandler, log)
	mux.Handle(pathHealthV1, healthHandler)

	// service specific health endpoint handler with wild card for service
	var userHealthHandler http.Handler
	userHealthHandler = http.HandlerFunc(s.handleSvcHealth)
	if cfg.enableCORS {
		userHealthHandler = corsHandler(userHealthHandler)
	}
	userHealthHandler = compMW(userHealthHandler)
	userHealthHandler = recoverer(userHealthHandler, log)
	mux.Handle(pathSvcHealthV1, userHealthHandler)

	return s, nil
}

// handleSvcHealth handles the /health/{svc} endpoint. This sets the HTTP status
// code in the response to 200 if the service indicates it is healthy, otherwise
// 503 (service unavailable). This is required to support common health checks
// in major cloud providers that are limited to a simple GET and which infer
// health exclusively based on the response status code.
//
// The response body includes a JSON object provided by the service.
func (s *Server) handleSvcHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	svcName := r.PathValue("svc")
	if svcName == "" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	svc, ok := s.services[svcName]
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	resp, happy := svc.Health(r.Context())
	status := http.StatusOK
	if !happy {
		status = http.StatusServiceUnavailable
	}
	s.writeJSON(w, resp, status)
	// an alternative approach is svc.HealthHandler(w, r)...
}

// jsonRPCTimeoutHandler runs the handler with a time limit. This middleware
// also logs the total request duration since it is a logical place that deals
// with request timing. This duration is the total elapsed duration that
// includes reading the full request, unmarshalling, running the corresponding
// method handler, marshalling the response, and transmitting the entire
// response to the client. This duration is at least as long as the time logged
// in processRequest, which pertains only to the handling of the request and
// thus reflects the server's computational burden, while this duration provides
// insight into the latencies introduced by bandwidth and marshalling.
func jsonRPCTimeoutHandler(h http.Handler, timeout time.Duration, logger log.Logger) http.Handler {
	// We'll respond with a jsonrpc.Response type, but the request handler is
	// downstream and we don't have the request ID.
	resp := jsonrpc.NewErrorResponse(-1, jsonrpc.NewError(jsonrpc.ErrorTimeout, "RPC timeout", nil))
	respMsg, _ := json.Marshal(resp)
	h = http.TimeoutHandler(h, timeout, string(respMsg)) // https://github.com/golang/go/issues/27375

	// Log total request handling time (including transfer).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now().UTC()
		defer func() {
			logger.Debug("request handling complete", "total_elapsed", time.Since(t0).String())
		}()
		// NOTE, to give downstream handlers access to t0 instead of a defer here:
		// ctx := context.WithValue(r.Context(), CtxStartTime, t0); r = r.WithContext(ctx)
		h.ServeHTTP(w, r)
	})
}

// corsHandler adds CORS headers to the response. We don't need sophisticated
// cors handling here (not really kwild's concern, there should be other services
// like LBs or KGW do that), so we just allow them.
// NOTE: if this server is served behind KGW, those headers will be stripped.
func corsHandler(h http.Handler) http.Handler {
	allowMethods := "GET, POST, OPTIONS"
	allowHeaders := "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, ResponseType, Range"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Methods", allowMethods)
		w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Preflight request
		if r.Method == http.MethodOptions {
			return
		}

		// Other SIMPLE requests and non-cors requests
		h.ServeHTTP(w, r)
	})
}

func recoverer(h http.Handler, log log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				if rvr == http.ErrAbortHandler {
					// we don't recover http.ErrAbortHandler so the response
					// to the client is aborted, this should not be logged
					panic(rvr)
				}

				debugStack := debug.Stack()
				log.Errorf("panic: %v\n%v", rvr, string(debugStack))

				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		h.ServeHTTP(w, r)
	})
}

func realIPHandler(h http.Handler, trustedProxyCount int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rip := realIP(r, trustedProxyCount); rip != "" {
			// r.RemoteAddr = rip
			r = r.WithContext(context.WithValue(r.Context(), RequestIPCtx, rip))
		}
		h.ServeHTTP(w, r)
	})
}

func addrHost(addr string) string {
	if net.ParseIP(addr) != nil {
		return addr
	}
	host, _, _ := net.SplitHostPort(addr)
	return host
}

// realIP is taken with minimum mods from kgw. This uses the "Trusted proxy
// count" method rather than the "Trusted proxy list" method.
func realIP(r *http.Request, xffTrustProxyCount int) string {
	if xffTrustProxyCount == 0 { // not behind any proxy
		return addrHost(r.RemoteAddr)
	}

	if xrip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xrip != "" {
		return xrip
	}

	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return addrHost(r.RemoteAddr)
	}

	parts := strings.Split(xff, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}

	// can only be the user ip
	if len(parts) == 1 {
		return parts[0]
	}

	// X-Forwarded-For: <clientIP>, <proxy1IP>, <proxy2IP>
	// -                    | 	        |           |
	// set by:            proxy1	  proxy2      proxy3
	// refer: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For#selecting_an_ip_address
	if len(parts) >= xffTrustProxyCount {
		return parts[len(parts)-xffTrustProxyCount]
	}

	return ""

}

// Addr returns the listener's address. This is only set after Server is called.
func (s *Server) Addr() string {
	return s.addr
}

func (s *Server) Serve(ctx context.Context) error {
	network := "tcp"
	if s.unix {
		network = "unix"
	}
	ln, err := net.Listen(network, s.srv.Addr)
	if err != nil {
		return err
	}
	if s.tlsCfg != nil {
		ln = tls.NewListener(ln, s.tlsCfg)
	}
	if s.unix {
		if err = os.Chmod(s.srv.Addr, 0755); err != nil {
			ln.Close()
			return err
		}
	}
	s.addr = ln.Addr().String()
	s.log.Info("JSON-RPC server listening", "address", s.addr)
	return s.ServeOn(ctx, ln)
}

func openRPCSpec(specInfo *openrpc.Info, methodDefs map[string]*openrpc.MethodDefinition) *openrpc.Spec {
	knownSchemas := make(map[reflect.Type]openrpc.Schema)
	methods := openrpc.InventoryAPI(methodDefs, knownSchemas)
	schemas := make(map[string]openrpc.Schema)
	for _, schema := range knownSchemas {
		schemas[schema.Name()] = schema
	}
	return &openrpc.Spec{
		OpenRPC: "1.2.4",
		Info:    *specInfo,
		Methods: methods,
		Components: openrpc.Components{
			Schemas: schemas,
		},
	}
}

func (s *Server) ServeOn(ctx context.Context, ln net.Listener) error {
	// With all services registered, only now can we generate the RPC spec.
	spec := openRPCSpec(s.specInfo, s.methodDefs)
	var err error
	s.spec, err = json.Marshal(spec)
	if err != nil {
		return err
	}

	s.RegisterMethodHandler(
		"rpc.discover",
		MakeMethodHandler(func(context.Context, *any) (*json.RawMessage, *jsonrpc.Error) {
			return &s.spec, nil
		}),
	)

	s.RegisterMethodHandler(
		"rpc.health",
		MakeMethodHandler(func(ctx context.Context, _ *any) (*json.RawMessage, *jsonrpc.Error) {
			healthResp := s.health(ctx)
			res, _ := json.Marshal(healthResp)
			resMsg := json.RawMessage(res)
			return &resMsg, nil
		}),
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.srv.Serve(ln)
		if !errors.Is(err, http.ErrServerClosed) {
			s.log.Warnf("unexpected (http.Server).Serve error: %v", err)
		}
		s.log.Infof("JSON-RPC listener done for %s", ln.Addr())
	}()

	// Shutdown the server on context cancellation.
	<-ctx.Done()

	s.log.Infof("JSON-RPC server shutting down...")
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.srv.Shutdown(ctxTimeout)
	if err != nil {
		err = fmt.Errorf("http.Server.Shutdown: %v", err)
	}

	wg.Wait()

	s.log.Infof("JSON-RPC server shutdown complete")
	return err
}

// handlerJSONRPCV1 handles all https JSON-RPC requests. It is the
// http.HandlerFunc for the JSON-RPC service mounted on the "/rpc/v1" endpoint.
// The endpoint is the same for all methods since this is JSON-RPC with a
// "method" field of the JSON request body indicating how to process the
// request. Other handlers can be mounted on other endpoints without worry. This
// method should only handle POST requests, so configure the request router as
// appropriate.
func (s *Server) handlerJSONRPCV1(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required for JSON-RPC", http.StatusMethodNotAllowed)
		return
	}

	// Close the connection when response handling is completed.
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Type", "application/json")
	r.Close = true

	if s.authSHA != nil {
		_, pass, haveAuth := r.BasicAuth() // r.Header.Get("Authorization")
		if !haveAuth {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Reveal nothing about the configured pass in verification time.
		authSHA := sha256.Sum256([]byte(pass))
		if subtle.ConstantTimeCompare(s.authSHA, authSHA[:]) != 1 {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	}

	/* stricter and inline decoding
	req := new(jsonrpc.Request)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(req)
	if err != nil {
		resp := jsonrpc.NewErrorResponse(-1, jsonrpc.NewError(jsonrpc.ErrorParse, "invalid request", nil))
		s.writeJSON(w, resp, http.StatusBadRequest)
		return
	}
	if dec.More() {
		resp := jsonrpc.NewErrorResponse(-1, jsonrpc.NewError(jsonrpc.ErrorParse, "extra data in request body", nil))
		s.writeJSON(w, resp, http.StatusBadRequest)
		return
	}*/

	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, "error reading request body", http.StatusBadRequest)
		return
	}
	req := new(jsonrpc.Request)
	err = json.Unmarshal(body, req)
	if err != nil {
		resp := jsonrpc.NewErrorResponse(-1, jsonrpc.NewError(jsonrpc.ErrorParse, "invalid request", nil))
		s.writeJSON(w, resp, http.StatusBadRequest)
		return
	}

	s.processJSONRPCRequest(r.Context(), w, req)
}

// processJSONRPCRequest handles the jsonrpc.Request with handleRequest to call the
// appropriate function for the method, creates a response message, and writes
// it to the http.ResponseWriter.
func (s *Server) processJSONRPCRequest(ctx context.Context, w http.ResponseWriter, req *jsonrpc.Request) {
	// Handle and time the request.
	resp := s.handleJSONRPCRequest(ctx, req)

	// Some conventions dictate 200 for everything, with the Response.Error
	// being the only sign of issue. However, a certain set of errors warrant an
	// http status code.
	statusCode := http.StatusOK
	if resp.Error != nil {
		switch resp.Error.Code {
		case jsonrpc.ErrorUnknownMethod: // other "not found" is not a 404 since the method at least existed
			statusCode = http.StatusNotFound // 404
		case jsonrpc.ErrorInvalidParams, jsonrpc.ErrorInvalidRequest, jsonrpc.ErrorParse:
			statusCode = http.StatusBadRequest // 400
		case jsonrpc.ErrorInternal:
			statusCode = http.StatusInternalServerError // 500
		}
	}

	// Write the response
	s.writeJSON(w, resp, statusCode)
}

// writeJSON marshals the provided interface and writes the bytes to
// the ResponseWriter with the specified response code.
func (s *Server) writeJSON(w http.ResponseWriter, thing any, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	b, err := json.Marshal(thing)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.log.Errorf("JSON encode error: %v", err)
		return
	}
	w.WriteHeader(code)
	_, err = w.Write(b)
	if err != nil {
		s.log.Errorf("Write error: %v", err)
	}
}

func zeroID(id any) bool {
	if id == nil {
		return true // would be !rv.IsValid()
	}
	rv := reflect.ValueOf(id)
	if rv.IsZero() {
		return true
	}
	rt := reflect.TypeOf(id) // already caught nil interface and nil ptr
	if rt.Kind() == reflect.Ptr {
		return zeroID(rv.Elem().Interface())
	}
	return false // already did rv.IsZero
}

// handleJSONRPCRequest sends the request to the correct handler function if able.
func (s *Server) handleJSONRPCRequest(ctx context.Context, req *jsonrpc.Request) *jsonrpc.Response {
	if req.JSONRPC != "2.0" || zeroID(req.ID) {
		rpcErr := jsonrpc.NewError(jsonrpc.ErrorInvalidRequest, "invalid json-rpc request object", nil)
		return jsonrpc.NewErrorResponse(req.ID, rpcErr)
	}
	if req.Method == "" {
		rpcErr := jsonrpc.NewError(jsonrpc.ErrorUnknownMethod, "no route was supplied", nil)
		return jsonrpc.NewErrorResponse(req.ID, rpcErr)
	}

	s.log.Debug("handling request", "method", req.Method)
	t0 := time.Now().UTC() // time only the handling (pertains to server utilization)

	// call the method with the params
	result, rpcErr := s.handleMethod(ctx, jsonrpc.Method(req.Method), req.Params)
	if rpcErr != nil {
		level := log.LevelInfo
		switch rpcErr.Code {
		case jsonrpc.ErrorInvalidParams, jsonrpc.ErrorInvalidRequest,
			jsonrpc.ErrorParse, jsonrpc.ErrorUnknownMethod,
			jsonrpc.ErrorTxNotFound, jsonrpc.ErrorBlkNotFound,
			jsonrpc.ErrorEngineDatasetNotFound:
			level = log.LevelDebug
		case jsonrpc.ErrorInternal, jsonrpc.ErrorTimeout, jsonrpc.ErrorResultEncoding:
			level = log.LevelWarn
		}
		s.log.Log(level, "request failure", "method", req.Method,
			"elapsed", time.Since(t0), "code", rpcErr.Code,
			"message", rpcErr.Message)

		return jsonrpc.NewErrorResponse(req.ID, rpcErr)
	}

	s.log.Debug("request success", "method", req.Method, "elapsed", time.Since(t0))

	resp, err := jsonrpc.NewResponse(req.ID, result)
	if err != nil { // failed to marshal result
		s.log.Error("failed to marshal result", "method", req.Method, "error", err)
		rpcErr := jsonrpc.NewError(jsonrpc.ErrorResultEncoding, "failed to encode result", nil)
		return jsonrpc.NewErrorResponse(req.ID, rpcErr)
	}
	return resp
}
