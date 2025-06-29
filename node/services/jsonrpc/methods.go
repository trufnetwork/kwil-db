package rpcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/openrpc"
)

// MethodHandler is a type of function that returns an interface containing a
// pointer to a handler's input arguments, and a handler function that captures
// the arguments pointer. The handler function returns its result type in an
// interface, and a *jsonrpc.Error. A simple MethodHandler would instantiate a
// new concrete instance of the parameters type and define a function that uses
// that instance to perform some operations.
type MethodHandler func(ctx context.Context, s *Server) (argsPtr any, handler func() (any, *jsonrpc.Error))

type Handler[I, O any] func(context.Context, *I) (*O, *jsonrpc.Error)

func ioTypes[I, O any](Handler[I, O]) (reflect.Type, reflect.Type) {
	return reflect.TypeFor[I](), reflect.TypeFor[O]()
}

func MakeMethodHandler[I, O any](fn Handler[I, O]) MethodHandler {
	return func(ctx context.Context, s *Server) (any, func() (any, *jsonrpc.Error)) {
		req := new(I)
		ctx = context.WithValue(ctx, ServerCtx, s)
		return req, func() (any, *jsonrpc.Error) { return fn(ctx, req) }
	}
}

func InspectHandler[I, O any](fn Handler[I, O]) (reflect.Type, reflect.Type, MethodHandler) {
	reqType, respType := ioTypes(fn)
	return reqType, respType, MakeMethodHandler(fn)
}

type MethodDef struct {
	Desc       string
	ParamDescs []string
	RespDesc   string
	Handler    MethodHandler
	ReqType    reflect.Type
	RespType   reflect.Type
}

func MakeMethodDef[I, O any](handler Handler[I, O], desc, respDesc string) MethodDef {
	iT, oT, rpcHandler := InspectHandler(handler)
	return MethodDef{
		Desc:     desc,
		RespDesc: respDesc,
		Handler:  rpcHandler,
		ReqType:  iT,
		RespType: oT,
	}
}

// Svc is a type that enumerates its handler functions by method name. To
// handle a method, the Server:
//  1. retrieves the MethodHandler associated with the method
//  2. calls the MethodHandler to get the args interface and handler function
//  3. unmarshals the inputs from a json.RawMessage into the args interface
//  4. calls the handler function, returning the result and error
//  5. marshal either the result or the Error into a Response
type Svc interface {
	// Name should return a unique name for the RPC service. This is intended
	// for meta endpoints provided by the RPC server, such as health checks.
	Name() string
	Methods() map[jsonrpc.Method]MethodDef
	Health(context.Context) (detail json.RawMessage, happy bool)
}

// RegisterSvc registers every MethodHandler for a service.
//
// The Server's fixed endpoint is used.
func (s *Server) RegisterSvc(svc Svc) {
	svcName := svc.Name()
	if _, have := s.services[svcName]; have {
		panic(fmt.Sprintf("service already registered: %s", svcName))
	}
	s.services[svcName] = svc

	for method, def := range svc.Methods() {
		s.log.Debugf("Registering method %q", method)
		s.RegisterMethodHandler(method, def.Handler)
		s.methodDefs[string(method)] = &openrpc.MethodDefinition{
			Description:  def.Desc,
			RequestType:  def.ReqType,
			ResponseType: def.RespType,
			RespTypeDesc: def.RespDesc,
		}
	}
}

func (s *Server) health(ctx context.Context) *jsonrpc.HealthResponse {
	resp := jsonrpc.HealthResponse{
		Alive:    true,
		Healthy:  true, // unless any one service is not
		Services: make(map[string]json.RawMessage, len(s.services)),
	}

	for _, svc := range s.services {
		svcResp, health := svc.Health(ctx)
		resp.Healthy = resp.Healthy && health
		resp.Services[svc.Name()] = svcResp
	}
	return &resp
}

func (s *Server) healthMethodHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	resp := s.health(r.Context())

	status := http.StatusOK
	if !resp.Healthy {
		status = http.StatusServiceUnavailable
	}
	s.writeJSON(w, resp, status)
}

// RegisterMethodHandler registers a single MethodHandler.
// See also RegisterSvc.
func (s *Server) RegisterMethodHandler(method jsonrpc.Method, h MethodHandler) {
	s.methodHandlers[method] = h
}

// handleMethod unmarshals into the appropriate params struct, and dispatches to
// the TxSvc method handler.
func (s *Server) handleMethod(ctx context.Context, method jsonrpc.Method, params json.RawMessage) (any, *jsonrpc.Error) {
	maker, have := s.methodHandlers[method]
	if !have {
		return nil, jsonrpc.NewError(jsonrpc.ErrorUnknownMethod, "unknown method", nil)
	}

	argsPtr, handler := maker(ctx, s)

	// Treat omitted params as null, which may or may not be acceptable
	// depending on the handler's parameters type. Otherwise json.Unmarshal
	// always errors with "unexpected end of JSON input".
	if params == nil {
		params = []byte(`null`)
	}

	err := json.Unmarshal(params, argsPtr)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, err.Error(), nil)
	}

	t0 := time.Now()
	var reqStatus int

	res, jsonRPCErr := handler()
	if jsonRPCErr != nil {
		reqStatus = int(jsonRPCErr.Code)
	}

	mets.RecordRequest(ctx, string(method), reqStatus, time.Since(t0))

	return res, jsonRPCErr
}
