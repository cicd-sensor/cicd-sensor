package celengine

import (
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// Primitive payload fields are pre-boxed to ref.Val on first access and
// cached. Without pre-boxing, cel-go's nativeToValue (provider.go:544)
// allocates types.String per per-rule access — pprof confirmed this is the
// dominant remaining cost after Direction 1 killed cext reflection.
// Returning ref.Val lets the cache hit nativeToValue's `case ref.Val:`
// short-circuit (provider.go:623).

// EventActivation resolves CEL event variables from a normalized event
// input and optionally delegates unknown names to a parent activation
// that supplies rule-static data such as predefined lists.
//
// Concurrency contract — single goroutine per activation. ResolveName
// mutates the cache map on first access of each field, and rule
// evaluation never parallelizes within a single event in this codebase
// (Job.runEventWorker is sequential; see internal/agent/job/job.go).
// To reuse the activation across events, the worker holds one
// *EventActivation and calls Reset(input) for each event. Parallelizing
// event evaluation would require either one activation per worker or
// reintroducing a pool — neither is in scope today, and Reset deliberately
// keeps that boundary obvious instead of hiding it behind sync.Pool.
type EventActivation struct {
	input  CELInputEvent
	parent cel.Activation
	cache  map[string]any
}

// NewEventActivation constructs an activation with an allocated cache
// map. Pass a zero CELInputEvent and call Reset on each event when reusing
// the same activation across an event loop; pass the input directly for
// test code that only evaluates a single event.
func NewEventActivation(input CELInputEvent) *EventActivation {
	return &EventActivation{input: input, cache: make(map[string]any, 8)}
}

// Reset re-initializes the activation for a new event. The cache map is
// retained but its entries are cleared so the previous event's
// types.String values become unreachable promptly (sensitive data like
// path / domain / remote_ip). Single-goroutine assumption: only the
// worker that owns this activation may call Reset / ResolveName, and
// never concurrently.
func (a *EventActivation) Reset(input CELInputEvent) {
	a.input = input
	a.parent = nil
	clear(a.cache)
}

// WithParent returns an activation that resolves event variables locally and
// defers unknown names to the parent activation.
func (a *EventActivation) WithParent(parent cel.Activation) *EventActivation {
	return &EventActivation{input: a.input, parent: parent}
}

// SetParent mutates the activation's parent in place.
func (a *EventActivation) SetParent(parent cel.Activation) {
	a.parent = parent
}

// Parent returns the parent activation, if any.
func (a *EventActivation) Parent() cel.Activation {
	return a.parent
}

// ResolveName resolves CEL variable names from the normalized event input.
// Boxed any values are cached on first access so repeated lookups across N
// rules share one eface header instead of reboxing per call.
func (a *EventActivation) ResolveName(name string) (any, bool) {
	if v, ok := a.cache[name]; ok {
		return v, true
	}
	value, ok := a.resolveLocal(name)
	if ok {
		if a.cache == nil {
			a.cache = make(map[string]any, 8)
		}
		a.cache[name] = value
		return value, true
	}
	if a.parent != nil {
		// Static parent activation supplies predefined lists as `list`.
		return a.parent.ResolveName(name)
	}
	return nil, false
}

func (a *EventActivation) resolveLocal(name string) (any, bool) {
	switch name {
	// Return a pointer so per-rule access avoids copying the CELProcess
	// struct (~80 bytes including cache fields) on each fieldQualifier
	// resolution. GetFrom closures type-assert *CELProcess.
	case "process":
		return &a.input.Process, true
	// process_exec.
	case "is_memfd":
		return types.Bool(a.input.IsMemfd), true
	// network_connect.
	case "remote_ip":
		return types.String(a.input.RemoteIP), true
	case "remote_port":
		return types.Int(a.input.RemotePort), true
	case "protocol":
		return types.String(a.input.Protocol), true
	case "family":
		return types.String(a.input.Family), true
	// Shared filesystem/socket path variable.
	case "path":
		return types.String(a.input.Path), true
	// file_open.
	case "is_write":
		return types.Bool(a.input.IsWrite), true
	case "is_read":
		return types.Bool(a.input.IsRead), true
	case "flags":
		return types.Int(a.input.Flags), true
	// file_remove.
	case "is_folder":
		return types.Bool(a.input.IsFolder), true
	// file_move.
	case "from_path":
		return types.String(a.input.FromPath), true
	case "to_path":
		return types.String(a.input.ToPath), true
	// file_link.
	case "created_path":
		return types.String(a.input.CreatedPath), true
	case "existing_path":
		return types.String(a.input.ExistingPath), true
	case "is_hardlink":
		return types.Bool(a.input.IsHardlink), true
	case "is_symlink":
		return types.Bool(a.input.IsSymlink), true
	// domain.
	case "domain":
		return types.String(a.input.Domain), true
	case "source":
		return types.String(a.input.Source), true
	// unix_socket_connect.
	case "socket_type":
		return types.String(a.input.SocketType), true
	case "is_abstract":
		return types.Bool(a.input.IsAbstract), true
	}
	return nil, false
}

func listsActivation(lists rule.PredefinedLists) map[string]any {
	if len(lists) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(lists))
	for key, values := range lists {
		// Pre-convert each element to types.String so exists() iterates
		// without per-element allocation.
		//
		// cel-go's *baseList.Get(i) always routes through NativeToValue.
		// NewStringList (and NativeToValue([]string)) backs the list with
		// []string, so every Get boxes a fresh types.String — one alloc per
		// iteration step. NewRefValList backs it with []ref.Val; NativeToValue
		// short-circuits on the already-boxed value, and Get returns the
		// cached instance. With dozens of rules running exists() over the
		// same lists per event, this is the dominant per-event allocation.
		celValues := make([]ref.Val, len(values))
		for i, v := range values {
			celValues[i] = types.String(v)
		}
		out[key] = newPredefinedList(celValues)
	}
	return out
}

// NewListActivation exposes predefined lists as the CEL `list` variable.
func NewListActivation(lists rule.PredefinedLists) (cel.Activation, error) {
	if len(lists) == 0 {
		return cel.NoVars(), nil
	}
	return cel.NewActivation(map[string]any{
		"list": listsActivation(lists),
	})
}
