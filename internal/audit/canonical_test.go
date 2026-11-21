package audit

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestCanonicalTestdata(t *testing.T) {
	raw, err := os.ReadFile("testdata/object.json")
	if err != nil {
		t.Fatal(err)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	got, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":2,"b":1,"n":0.000001}` {
		t.Fatalf("%s", got)
	}
}

func TestCanonicalVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{`{"10":1,"1":2}`, `{"1":2,"10":1}`},
		{`[true,false,null]`, `[true,false,null]`},
		{`{"n":0}`, `{"n":0}`},
		{`{"n":-0}`, `{"n":0}`},
		{`{"n":1.0}`, `{"n":1}`},
		{`{"n":10}`, `{"n":10}`},
		{`{"n":1.5}`, `{"n":1.5}`},
		{`{"n":1e+21}`, `{"n":1e+21}`},
		{`{"n":1e+20}`, `{"n":100000000000000000000}`},
		{`{"n":1e-6}`, `{"n":0.000001}`},
		{`{"n":1e-7}`, `{"n":1e-7}`},
		{`{"esc":"a\"b\\c"}`, `{"esc":"a\"b\\c"}`},
		{"{\"u\":\"é\"}", `{"u":"é"}`},
	}
	for _, tc := range cases {
		var v any
		dec := json.NewDecoder(strings.NewReader(tc.in))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		got, err := Canonical(v)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if string(got) != tc.want {
			t.Fatalf("%s\n got %s\nwant %s", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalUTF16Order(t *testing.T) {
	// U+10000 encodes as the surrogate pair D800 DC00, so it sorts before U+FFFF.
	in := map[string]any{"a": 1, "\uFFFF": 2, "\U00010000": 3}
	got, err := Canonical(in)
	if err != nil {
		t.Fatal(err)
	}
	a := bytes.Index(got, []byte(`"a"`))
	ffff := bytes.Index(got, []byte("\uFFFF"))
	astral := bytes.Index(got, []byte("\U00010000"))
	if !(a >= 0 && a < astral && astral < ffff) {
		t.Fatalf("order %s", got)
	}
}

func TestAuditPackageImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "net/http" || strings.Contains(p, "/internal/store") || strings.Contains(p, "/internal/api") {
				t.Errorf("%s imports %s", e.Name(), p)
			}
		}
	}
}

func FuzzCanonical(f *testing.F) {
	f.Add([]byte(`{"b":1,"a":"x"}`))
	f.Add([]byte(`[true,null,0.1,"a\"b"]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return
		}
		out, err := Canonical(v)
		if err != nil {
			return
		}
		again, err := Canonical(json.RawMessage(out))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, again) {
			t.Fatalf("not stable\n%s\n%s", out, again)
		}
	})
}
