package common

import (
	"fmt"
	"sort"
	"time"
)

const (
	EngineTraceKindAction     = "action"
	EngineTraceKindPrecompile = "precompile"
	EngineTraceKindSQL        = "sql"
	EngineTraceKindRuntime    = "runtime"
)

// EngineTrace collects exclusive-time Engine.Call stages for one transaction.
// Nil receivers are no-ops so unrelated callers pay nothing.
type EngineTrace struct {
	stages map[engineTraceKey]*engineTraceAcc
	stack  []engineTraceFrame
}

type engineTraceKey struct {
	kind      string
	namespace string
	name      string
	parent    string
}

type engineTraceAcc struct {
	count     int
	total     time.Duration
	exclusive time.Duration
	max       time.Duration
}

type engineTraceFrame struct {
	key       engineTraceKey
	started   time.Time
	childWall time.Duration
}

// EngineTraceStage is a summable exclusive-time aggregate for one stage key.
type EngineTraceStage struct {
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	Parent      string `json:"parent,omitempty"`
	Count       int    `json:"count"`
	TotalMs     int64  `json:"total_ms"`
	ExclusiveMs int64  `json:"exclusive_ms"`
	MaxMs       int64  `json:"max_ms"`
}

func (s EngineTraceStage) String() string {
	return fmt.Sprintf(
		"{kind=%s namespace=%s name=%s parent=%s count=%d exclusive_ms=%d total_ms=%d max_ms=%d}",
		s.Kind,
		s.Namespace,
		s.Name,
		s.Parent,
		s.Count,
		s.ExclusiveMs,
		s.TotalMs,
		s.MaxMs,
	)
}

func NewEngineTrace() *EngineTrace {
	return &EngineTrace{
		stages: make(map[engineTraceKey]*engineTraceAcc),
	}
}

// Start begins a nested stage. The returned function records exclusive time
// and must be called exactly once, including on error paths.
func (t *EngineTrace) Start(kind, namespace, name, parent string) func() {
	if t == nil {
		return func() {}
	}
	key := engineTraceKey{kind: kind, namespace: namespace, name: name, parent: parent}
	t.stack = append(t.stack, engineTraceFrame{
		key:     key,
		started: time.Now(),
	})
	return func() {
		if len(t.stack) == 0 {
			return
		}
		frame := t.stack[len(t.stack)-1]
		t.stack = t.stack[:len(t.stack)-1]
		elapsed := time.Since(frame.started)
		exclusive := elapsed - frame.childWall
		if exclusive < 0 {
			exclusive = 0
		}
		acc := t.stages[frame.key]
		if acc == nil {
			acc = &engineTraceAcc{}
			t.stages[frame.key] = acc
		}
		acc.count++
		acc.total += elapsed
		acc.exclusive += exclusive
		if exclusive > acc.max {
			acc.max = exclusive
		}
		if len(t.stack) > 0 {
			t.stack[len(t.stack)-1].childWall += elapsed
		}
	}
}

// ParentName is the innermost action or precompile currently on the stack.
func (t *EngineTrace) ParentName() string {
	if t == nil {
		return ""
	}
	for i := len(t.stack) - 1; i >= 0; i-- {
		switch t.stack[i].key.kind {
		case EngineTraceKindAction, EngineTraceKindPrecompile:
			return t.stack[i].key.name
		}
	}
	return ""
}

// Stages returns exclusive-time aggregates, largest exclusive first.
func (t *EngineTrace) Stages() []EngineTraceStage {
	if t == nil || len(t.stages) == 0 {
		return nil
	}
	out := make([]EngineTraceStage, 0, len(t.stages))
	for key, acc := range t.stages {
		out = append(out, EngineTraceStage{
			Kind:        key.kind,
			Namespace:   key.namespace,
			Name:        key.name,
			Parent:      key.parent,
			Count:       acc.count,
			TotalMs:     acc.total.Milliseconds(),
			ExclusiveMs: acc.exclusive.Milliseconds(),
			MaxMs:       acc.max.Milliseconds(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if left.ExclusiveMs != right.ExclusiveMs {
			return left.ExclusiveMs > right.ExclusiveMs
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.Parent < right.Parent
	})
	return out
}
