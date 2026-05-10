package syrup

import (
	"bytes"
	"testing"
)

// go-fed/syrup uses the old Spritely wire format (i42e) by default via
// NewPrototypeEncoding(). We benchmark that directly since it is the only
// encoder/decoder available in this package.

var enc = NewPrototypeEncoding()

// --- Encode benchmarks ---

func BenchmarkEncodeInt(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode(int64(42)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeString(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode("hello world"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeBytes(b *testing.B) {
	payload := []byte("hello world")
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeSymbol(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode(Symbol("op:deliver")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeBool(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode(true); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeFloat64(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode(float64(3.14)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeRecord(b *testing.B) {
	rec := Record{
		Label:  "op:deliver",
		Values: []interface{}{int64(1), Symbol("answer"), "hello"},
	}
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode(rec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeList100(b *testing.B) {
	items := make([]interface{}, 100)
	for i := range items {
		items[i] = int64(i)
	}
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode(items); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Decode benchmarks ---

func BenchmarkDecodeInt(b *testing.B) {
	// go-fed encodes as i42e
	encoded := enc.fmtInt(42)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v int64
		if err := d.Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeString(b *testing.B) {
	encoded := enc.fmtString("hello world")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v string
		if err := d.Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeBytes(b *testing.B) {
	encoded := enc.fmtBytes([]byte("hello world"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v []byte
		if err := d.Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeSymbol(b *testing.B) {
	encoded := enc.fmtSymbol("op:deliver")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v Symbol
		if err := d.Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeBool(b *testing.B) {
	encoded := enc.fmtBool(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v bool
		if err := d.Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeRecord(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	rec := Record{
		Label:  "op:deliver",
		Values: []interface{}{int64(1), Symbol("answer"), "hello"},
	}
	if err := w.Encode(rec); err != nil {
		b.Fatal(err)
	}
	encoded := make([]byte, buf.Len())
	copy(encoded, buf.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v Record
		if err := d.Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeList100(b *testing.B) {
	items := make([]interface{}, 100)
	for i := range items {
		items[i] = int64(i)
	}
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	if err := w.Encode(items); err != nil {
		b.Fatal(err)
	}
	encoded := make([]byte, buf.Len())
	copy(encoded, buf.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v []interface{}
		if err := d.Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}
