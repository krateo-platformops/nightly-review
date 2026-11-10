// Package pg is the one Postgres connection the service opens: kagent's database, read with a role
// granted SELECT on `session` and `event` and nothing else. It keeps pg8000.native's calling convention —
// conn.run(sql, **named) with :name placeholders, rows as tuples — because the queries are written that
// way and their tests assert the arguments by name.
package pg

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	_ "github.com/lib/pq" // pure Go, as pg8000 was pure Python: no libpq in the image
)

// Conn is pg8000.native.Connection as the service uses it.
type Conn interface {
	Run(ctx context.Context, query string, args map[string]any) ([][]any, error)
	Close() error
}

// Params are pg8000.native.Connection's keyword arguments.
type Params struct {
	User, Password, Host, Database string
	Port                           int
	Timeout                        time.Duration
}

// Connect opens a connection. A variable so a test can stand in for the database.
var Connect = func(ctx context.Context, p Params) (Conn, error) {
	u := &url.URL{Scheme: "postgres", User: url.UserPassword(p.User, p.Password),
		Host: p.Host + ":" + strconv.Itoa(p.Port), Path: "/" + p.Database}
	q := url.Values{}
	// pg8000's default is no TLS (ssl_context=None); lib/pq's would be to require it.
	q.Set("sslmode", "disable")
	q.Set("connect_timeout", strconv.Itoa(int(p.Timeout.Seconds())))
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	cctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	if err := db.PingContext(cctx); err != nil {
		db.Close()
		return nil, err
	}
	return &conn{db: db, timeout: p.Timeout}, nil
}

type conn struct {
	db      *sql.DB
	timeout time.Duration
}

func (c *conn) Close() error { return c.db.Close() }

// Run executes one statement with pg8000's named placeholders and returns every row.
func (c *conn) Run(ctx context.Context, query string, args map[string]any) ([][]any, error) {
	stmt, names := ToStatement(query)
	vals := make([]any, len(names))
	for i, n := range names {
		v, ok := args[n]
		if !ok {
			return nil, fmt.Errorf("missing parameter %s", n)
		}
		vals[i] = v
	}
	qctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	rows, err := c.db.QueryContext(qctx, stmt, vals...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]any
	for rows.Next() {
		row := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range row {
			ptrs[i] = &row[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range row {
			if b, ok := v.([]byte); ok { // text columns arrive as bytes from lib/pq
				row[i] = string(b)
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ToStatement ports pg8000.native.to_statement: :name placeholders become $1, $2… (a repeated name
// reuses its number), except inside quotes, quoted identifiers, dollar quotes and -- comments, and
// except `::` casts and `:=`.
func ToStatement(query string) (string, []string) {
	const (
		out = iota
		inSQ
		inQI
		inES
		inPN
		inCO
		inDQ
	)
	rs := []rune(query)
	state := out
	inQuoteEscape := false
	var placeholders []string
	var b strings.Builder
	var prev rune = -1
	for i, c := range rs {
		var next rune = -1
		if i+1 < len(rs) {
			next = rs[i+1]
		}
		switch state {
		case out:
			switch {
			case c == '\'':
				b.WriteRune(c)
				if prev == 'E' {
					state = inES
				} else {
					state = inSQ
				}
			case c == '"':
				b.WriteRune(c)
				state = inQI
			case c == '-':
				b.WriteRune(c)
				if prev == '-' {
					state = inCO
				}
			case c == '$':
				b.WriteRune(c)
				if prev == '$' {
					state = inDQ
				}
			case c == ':' && next != ':' && next != '=' && next != -1 && prev != ':':
				state = inPN
				placeholders = append(placeholders, "")
			default:
				b.WriteRune(c)
			}
		case inSQ:
			if c == '\'' {
				switch {
				case inQuoteEscape:
					inQuoteEscape = false
				case next == '\'':
					inQuoteEscape = true
				default:
					state = out
				}
			}
			b.WriteRune(c)
		case inQI:
			if c == '"' {
				state = out
			}
			b.WriteRune(c)
		case inES:
			if c == '\'' && prev != '\\' {
				state = out
			}
			b.WriteRune(c)
		case inPN:
			placeholders[len(placeholders)-1] += string(c)
			if next == -1 || (!isAlnum(next) && next != '_') {
				state = out
				last := placeholders[len(placeholders)-1]
				idx := -1
				for j, p := range placeholders[:len(placeholders)-1] {
					if p == last {
						idx = j
						break
					}
				}
				if idx >= 0 {
					fmt.Fprintf(&b, "$%d", idx+1)
					placeholders = placeholders[:len(placeholders)-1]
				} else {
					fmt.Fprintf(&b, "$%d", len(placeholders))
				}
			}
		case inCO:
			b.WriteRune(c)
			if c == '\n' {
				state = out
			}
		case inDQ:
			b.WriteRune(c)
			if c == '$' && prev == '$' {
				state = out
			}
		}
		prev = c
	}
	return b.String(), placeholders
}

func isAlnum(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.N, r)
}
