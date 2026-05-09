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
		_ = w.Encode(int64(42))
	}
}

func BenchmarkEncodeString(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = w.Encode("hello world")
	}
}

func BenchmarkEncodeBytes(b *testing.B) {
	payload := []byte("hello world")
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = w.Encode(payload)
	}
}

func BenchmarkEncodeSymbol(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = w.Encode(Symbol("op:deliver"))
	}
}

func BenchmarkEncodeBool(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = w.Encode(true)
	}
}

func BenchmarkEncodeFloat64(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = w.Encode(float64(3.14))
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
		_ = w.Encode(rec)
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
		_ = w.Encode(items)
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
		_ = d.Decode(&v)
	}
}

func BenchmarkDecodeString(b *testing.B) {
	encoded := enc.fmtString("hello world")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v string
		_ = d.Decode(&v)
	}
}

func BenchmarkDecodeBytes(b *testing.B) {
	encoded := enc.fmtBytes([]byte("hello world"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v []byte
		_ = d.Decode(&v)
	}
}

func BenchmarkDecodeSymbol(b *testing.B) {
	encoded := enc.fmtSymbol("op:deliver")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v Symbol
		_ = d.Decode(&v)
	}
}

func BenchmarkDecodeBool(b *testing.B) {
	encoded := enc.fmtBool(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v bool
		_ = d.Decode(&v)
	}
}

func BenchmarkDecodeRecord(b *testing.B) {
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	rec := Record{
		Label:  "op:deliver",
		Values: []interface{}{int64(1), Symbol("answer"), "hello"},
	}
	_ = w.Encode(rec)
	encoded := make([]byte, buf.Len())
	copy(encoded, buf.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v Record
		_ = d.Decode(&v)
	}
}

func BenchmarkDecodeList100(b *testing.B) {
	items := make([]interface{}, 100)
	for i := range items {
		items[i] = int64(i)
	}
	var buf bytes.Buffer
	w := NewEncoder(enc, &buf)
	_ = w.Encode(items)
	encoded := make([]byte, buf.Len())
	copy(encoded, buf.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		d := NewDecoder(enc, r)
		var v []interface{}
		_ = d.Decode(&v)
	}
}
