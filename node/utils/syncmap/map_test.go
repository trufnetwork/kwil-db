package syncmap_test

import (
	"testing"

	"github.com/trufnetwork/kwil-db/node/utils/syncmap"
)

func Test_SyncMap(t *testing.T) {
	var m syncmap.Map[string, string]

	m.Set("hello", "world")
	m.Set("foo", "bar")

	value, ok := m.Get("hello")
	if !ok {
		t.Fatal("expected ok")
	}

	if value != "world" {
		t.Fatal("expected world")
	}

	value, ok = m.Get("foo")
	if !ok {
		t.Fatal("expected ok")
	}

	if value != "bar" {
		t.Fatal("expected bar")
	}

	m.Exclusive(func(m map[string]string) {
		_, foundHello := m["hello"]
		if !foundHello {
			t.Fatal("expected foundHello")
		}

		_, foundFoo := m["foo"]
		if !foundFoo {
			t.Fatal("expected foundFoo")
		}
	})

	m.Delete("hello")

	_, ok = m.Get("hello")
	if ok {
		t.Fatal("expected !ok")
	}

	m.Clear()

	_, ok = m.Get("foo")
	if ok {
		t.Fatal("expected !ok")
	}
}
