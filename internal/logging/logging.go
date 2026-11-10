// Package logging is the service's one logger: log/slog, JSON lines on stdout, where the Python service
// printed. Each message is the exact line the Python service printed ("[run] …", "[publish] …"), so
// anything that searched the old logs still finds the same text, now inside a structured record.
//
// THE SEAM FOR TRACING. Every call takes a context.Context; when the service adopts provider-runtime's
// OTel handler, it replaces Default's handler here and the trace and span ids ride along on every
// record without touching a caller.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Default is the logger every package writes through.
var Default = New(os.Stdout)

// New returns a JSON logger writing to w.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// Printf logs one line at info level.
func Print(ctx context.Context, msg string) { Default.InfoContext(ctx, msg) }
