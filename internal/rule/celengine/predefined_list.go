package celengine

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// predefinedList is the Lister used for predefined-list activation values.
// It stores the pre-boxed elements directly and keeps one reusable iterator
// embedded, so `.exists()` macros over the list do not allocate a fresh
// iterator on every invocation. Rule evaluation is single-goroutine per
// event (see EventActivation doc), so the embedded iterator is reused
// sequentially without locking. Parallel evaluation would need a sync.Pool
// here.
type predefinedList struct {
	elems []ref.Val
	iter  predefinedListIter
}

func newPredefinedList(elems []ref.Val) *predefinedList {
	l := &predefinedList{elems: elems}
	l.iter.owner = l
	return l
}

// --- traits.Lister ---

func (l *predefinedList) Iterator() traits.Iterator {
	l.iter.idx = 0
	return &l.iter
}

func (l *predefinedList) Size() ref.Val { return types.Int(len(l.elems)) }

func (l *predefinedList) Get(idx ref.Val) ref.Val {
	i, ok := idx.(types.Int)
	if !ok {
		return types.ValOrErr(idx, "list index must be an int")
	}
	if i < 0 || int(i) >= len(l.elems) {
		return types.NewErr("index out of range: %d", i)
	}
	return l.elems[i]
}

func (l *predefinedList) Contains(value ref.Val) ref.Val {
	for _, e := range l.elems {
		if e.Equal(value) == types.True {
			return types.True
		}
	}
	return types.False
}

func (l *predefinedList) Add(other ref.Val) ref.Val {
	// Predefined lists are immutable inputs to CEL; rules cannot extend
	// them. Returning an error is consistent with cel-go's behavior for
	// frozen lists.
	return types.NewErr("predefined list does not support add")
}

// --- ref.Val ---

func (l *predefinedList) Type() ref.Type { return types.ListType }

func (l *predefinedList) Value() any {
	out := make([]any, len(l.elems))
	for i, e := range l.elems {
		out[i] = e.Value()
	}
	return out
}

func (l *predefinedList) Equal(other ref.Val) ref.Val {
	o, ok := other.(*predefinedList)
	if !ok {
		return types.False
	}
	if len(l.elems) != len(o.elems) {
		return types.False
	}
	for i, e := range l.elems {
		if e.Equal(o.elems[i]) != types.True {
			return types.False
		}
	}
	return types.True
}

func (l *predefinedList) ConvertToType(t ref.Type) ref.Val {
	if t == types.TypeType {
		return types.ListType
	}
	if t == types.ListType {
		return l
	}
	return types.NewErr("type conversion not supported from list to %v", t)
}

func (l *predefinedList) ConvertToNative(t reflect.Type) (any, error) {
	if t.Kind() != reflect.Slice {
		return nil, fmt.Errorf("native conversion not supported from list to %v", t)
	}
	out := reflect.MakeSlice(t, len(l.elems), len(l.elems))
	for i, e := range l.elems {
		v, err := e.ConvertToNative(t.Elem())
		if err != nil {
			return nil, err
		}
		out.Index(i).Set(reflect.ValueOf(v))
	}
	return out.Interface(), nil
}

// predefinedListIter is embedded in predefinedList so Iterator() can
// return a pointer to it without allocating.
type predefinedListIter struct {
	owner *predefinedList
	idx   int
}

func (it *predefinedListIter) HasNext() ref.Val {
	if it.idx < len(it.owner.elems) {
		return types.True
	}
	return types.False
}

func (it *predefinedListIter) Next() ref.Val {
	v := it.owner.elems[it.idx]
	it.idx++
	return v
}

// ref.Val on the iterator (required by traits.Iterator).
func (it *predefinedListIter) Type() ref.Type        { return types.IteratorType }
func (it *predefinedListIter) Value() any            { return nil }
func (it *predefinedListIter) Equal(ref.Val) ref.Val { return types.False }
func (it *predefinedListIter) ConvertToType(t ref.Type) ref.Val {
	return types.NewErr("iterator does not support type conversion")
}
func (it *predefinedListIter) ConvertToNative(reflect.Type) (any, error) {
	return nil, nil
}
