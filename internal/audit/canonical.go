package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonical returns RFC 8785 JSON Canonicalization Scheme bytes.
// Structs are first converted with encoding/json, then object keys are sorted
// by UTF-16 code units and numbers are re-serialized with the ECMAScript rules.
// An in-repo implementation keeps the record format free of a new dependency;
// the vectors in canonical_test.go pin the behavior.
func Canonical(content any) ([]byte, error) {
	raw, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, x)
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return errors.New("non-finite number")
		}
		s, err := es6Number(f)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return errors.New("non-finite number")
		}
		s, err := es6Number(x)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, el := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return errors.New("unsupported canonical value")
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigit(byte(r) >> 4))
				buf.WriteByte(hexDigit(byte(r) & 0xf))
				continue
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

func utf16Less(a, b string) bool {
	aa, bb := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	n := len(aa)
	if len(bb) < n {
		n = len(bb)
	}
	for i := 0; i < n; i++ {
		if aa[i] != bb[i] {
			return aa[i] < bb[i]
		}
	}
	return len(aa) < len(bb)
}

// es6Number serializes an IEEE-754 value the way ECMAScript NumberToString does,
// which is the number format RFC 8785 requires.
func es6Number(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("non-finite number")
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	raw := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, err := splitSci(raw)
	if err != nil {
		return "", err
	}
	k := len(mant)
	n := exp + 1
	switch {
	case k <= n && n <= 21:
		return sign + mant + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + mant[:n] + "." + mant[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + mant, nil
	default:
		out := sign + mant[:1]
		if k > 1 {
			out += "." + mant[1:]
		}
		out += "e"
		ee := n - 1
		if ee < 0 {
			out += "-"
			ee = -ee
		} else {
			out += "+"
		}
		out += strconv.Itoa(ee)
		return out, nil
	}
}

func splitSci(s string) (string, int, error) {
	e := strings.IndexAny(s, "eE")
	if e < 0 {
		return "", 0, errors.New("bad scientific form")
	}
	exp, err := strconv.Atoi(s[e+1:])
	if err != nil {
		return "", 0, err
	}
	head := strings.ReplaceAll(s[:e], ".", "")
	head = strings.TrimLeft(head, "0")
	if head == "" {
		head = "0"
	}
	return head, exp, nil
}
