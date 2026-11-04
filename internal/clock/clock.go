// Package clock provides a time abstraction for testing.
package clock

import "time"

// Clock is a source of time. Production code uses Real; tests use clocktest.Fake.
type Clock interface {
	Now() time.Time
}

// Real is a Clock that returns the current wall-clock time.
type Real struct{}

// Now returns time.Now().
func (Real) Now() time.Time {
	return time.Now()
}

// Or returns c if non-nil, otherwise Real{}.
func Or(c Clock) Clock {
	if c == nil {
		return Real{}
	}
	return c
}
