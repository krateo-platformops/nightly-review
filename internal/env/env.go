// Package env reads the service's configuration from the environment the way the Python modules did
// at import time: os.environ.get(name, default), and int() over it — so a value that does not parse
// stops the process at start, before anything is read or written.
package env

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Str is os.environ.get(name, def).
func Str(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

// Int is int(os.environ.get(name, def)).
func Int(name, def string) int { return mustInt(name, Str(name, def)) }

// IntOr is int(os.environ.get(name) or def): an empty value means the default too.
func IntOr(name, def string) int {
	v := os.Getenv(name)
	if v == "" {
		v = def
	}
	return mustInt(name, v)
}

// ParseInt is Python's int(str): surrounding whitespace, a sign, and single underscores between digits.
func ParseInt(s string) (int, error) {
	t := strings.TrimSpace(s)
	sign := ""
	if strings.HasPrefix(t, "+") || strings.HasPrefix(t, "-") {
		sign, t = t[:1], t[1:]
	}
	if t == "" || strings.HasPrefix(t, "_") || strings.HasSuffix(t, "_") || strings.Contains(t, "__") {
		return 0, fmt.Errorf("invalid literal for int() with base 10: %q", s)
	}
	n, err := strconv.Atoi(sign + strings.ReplaceAll(t, "_", ""))
	if err != nil {
		return 0, fmt.Errorf("invalid literal for int() with base 10: %q", s)
	}
	return n, nil
}

func mustInt(name, v string) int {
	n, err := ParseInt(v)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	return n
}
