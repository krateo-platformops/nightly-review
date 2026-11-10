package py

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Now is datetime.now(timezone.utc): Python keeps microseconds, never nanoseconds.
func Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// Isoformat is datetime.isoformat() for an aware datetime: microseconds only when non-zero, and the
// offset as +HH:MM (+00:00 for UTC — never "Z").
func Isoformat(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	_, off := t.Zone()
	sign := "+"
	if off < 0 {
		sign = "-"
		off = -off
	}
	s += fmt.Sprintf("%s%02d:%02d", sign, off/3600, (off%3600)/60)
	if off%60 != 0 {
		s += fmt.Sprintf(":%02d", off%60)
	}
	return s
}

// FromISOFormat is datetime.fromisoformat(s) as CPython 3.12's C implementation reads it, returning
// the time and whether it carried an offset (a naive datetime has none). Accepted: YYYY-MM-DD,
// YYYYMMDD and the ISO week forms; any single character as the separator; HH[:MM[:SS[.f…]]] or the
// basic HHMMSS forms; Z or ±HH[:MM[:SS[.ffffff]]] offsets.
func FromISOFormat(s string) (t time.Time, aware bool, err error) {
	bad := fmt.Errorf("Invalid isoformat string: %s", StrRepr(s))
	if utf8.RuneCountInString(s) < 7 {
		return time.Time{}, false, bad
	}
	runes := []rune(s)
	sep, ok := isoSeparator(runes)
	if !ok {
		return time.Time{}, false, bad
	}
	dstr := string(runes[:sep])
	tstr := ""
	if sep+1 <= len(runes) {
		if sep < len(runes) {
			tstr = string(runes[sep+1:])
		}
	}
	y, mo, d, ok := isoDate(dstr)
	if !ok {
		return time.Time{}, false, bad
	}
	hh, mm, ss, us := 0, 0, 0, 0
	loc := time.UTC
	if tstr != "" {
		var tz *time.Location
		hh, mm, ss, us, tz, ok = isoTime(tstr)
		if !ok {
			return time.Time{}, false, bad
		}
		if tz != nil {
			loc, aware = tz, true
		}
	}
	if mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) || hh > 23 || mm > 59 || ss > 59 {
		return time.Time{}, false, bad
	}
	return time.Date(y, time.Month(mo), d, hh, mm, ss, us*1000, loc), aware, nil
}

func daysIn(y, m int) int { return time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day() }

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// isoSeparator ports _find_isoformat_datetime_separator.
func isoSeparator(s []rune) (int, bool) {
	n := len(s)
	if n == 7 {
		return 7, true
	}
	if s[4] == '-' {
		if s[5] == 'W' {
			if n < 8 {
				return 0, false
			}
			if n > 8 && s[8] == '-' {
				if n == 9 {
					return 0, false
				}
				if n > 10 && isDigit(s[10]) {
					return 8, true
				}
				return 10, true
			}
			return 8, true
		}
		return 10, true
	}
	if s[4] == 'W' {
		idx := 7
		for idx < n && isDigit(s[idx]) {
			idx++
		}
		if idx < 9 {
			return idx, true
		}
		if idx%2 == 0 {
			return 7, true
		}
		return 8, true
	}
	return 8, true
}

func digits(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if !isDigit(r) {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func isoDate(s string) (y, m, d int, ok bool) {
	if len(s) != 7 && len(s) != 8 && len(s) != 10 {
		return 0, 0, 0, false
	}
	if y, ok = digits(s[0:4]); !ok {
		return
	}
	hasSep := s[4] == '-'
	pos := 4
	if hasSep {
		pos++
	}
	if pos < len(s) && s[pos] == 'W' {
		pos++
		if pos+2 > len(s) {
			return 0, 0, 0, false
		}
		week, ok2 := digits(s[pos : pos+2])
		if !ok2 {
			return 0, 0, 0, false
		}
		pos += 2
		day := 1
		if len(s) > pos {
			if (s[pos] == '-') != hasSep {
				return 0, 0, 0, false
			}
			if hasSep {
				pos++
			}
			if pos+1 > len(s) {
				return 0, 0, 0, false
			}
			if day, ok2 = digits(s[pos : pos+1]); !ok2 {
				return 0, 0, 0, false
			}
		}
		if week < 1 || week > 53 || day < 1 || day > 7 {
			return 0, 0, 0, false
		}
		jan4 := time.Date(y, 1, 4, 0, 0, 0, 0, time.UTC)
		wd := int(jan4.Weekday())
		if wd == 0 {
			wd = 7
		}
		monday := jan4.AddDate(0, 0, 1-wd)
		t := monday.AddDate(0, 0, (week-1)*7+day-1)
		if week == 53 && t.Year() != y && t.AddDate(0, 0, -(day-1)).Year() != y {
			return 0, 0, 0, false
		}
		return t.Year(), int(t.Month()), t.Day(), true
	}
	if pos+2 > len(s) {
		return 0, 0, 0, false
	}
	if m, ok = digits(s[pos : pos+2]); !ok {
		return
	}
	pos += 2
	if pos >= len(s) {
		return 0, 0, 0, false
	}
	if (s[pos] == '-') != hasSep {
		return 0, 0, 0, false
	}
	if hasSep {
		pos++
	}
	if pos+2 != len(s) {
		return 0, 0, 0, false
	}
	d, ok = digits(s[pos : pos+2])
	return
}

// hhmmssff ports _parse_hh_mm_ss_ff.
func hhmmssff(s string) (comps [4]int, ok bool) {
	pos := 0
	hasSep := false
	for comp := 0; comp < 3; comp++ {
		if len(s)-pos < 2 {
			return comps, false
		}
		n, ok2 := digits(s[pos : pos+2])
		if !ok2 {
			return comps, false
		}
		comps[comp] = n
		pos += 2
		next := ""
		if pos < len(s) {
			next = s[pos : pos+1]
		}
		if comp == 0 {
			hasSep = next == ":"
		}
		if next == "" || comp >= 2 {
			break
		}
		if hasSep && next != ":" {
			return comps, false
		}
		if hasSep {
			pos++
		}
	}
	if pos < len(s) {
		if s[pos] != '.' && s[pos] != ',' {
			return comps, false
		}
		pos++
		rem := len(s) - pos
		if rem == 0 {
			return comps, false
		}
		take := rem
		if take > 6 {
			take = 6
		}
		n, ok2 := digits(s[pos : pos+take])
		if !ok2 {
			return comps, false
		}
		for i := take; i < 6; i++ {
			n *= 10
		}
		comps[3] = n
		if rem > take {
			if _, ok2 := digits(s[pos+take:]); !ok2 {
				return comps, false
			}
		}
	}
	return comps, true
}

func isoTime(s string) (hh, mm, ss, us int, tz *time.Location, ok bool) {
	if len(s) < 2 {
		return
	}
	tzPos := strings.IndexAny(s, "-") + 1
	if tzPos == 0 {
		tzPos = strings.IndexAny(s, "+") + 1
	}
	if tzPos == 0 {
		tzPos = strings.IndexAny(s, "Z") + 1
	}
	timestr := s
	if tzPos > 0 {
		timestr = s[:tzPos-1]
	}
	comps, ok := hhmmssff(timestr)
	if !ok {
		return
	}
	hh, mm, ss, us = comps[0], comps[1], comps[2], comps[3]
	if tzPos == len(s) && s[len(s)-1] == 'Z' {
		return hh, mm, ss, us, time.UTC, true
	}
	if tzPos > 0 {
		tzstr := s[tzPos:]
		if len(tzstr) == 0 || len(tzstr) == 1 || len(tzstr) == 3 {
			return 0, 0, 0, 0, nil, false
		}
		tc, ok2 := hhmmssff(tzstr)
		if !ok2 {
			return 0, 0, 0, 0, nil, false
		}
		secs := tc[0]*3600 + tc[1]*60 + tc[2]
		if secs >= 86400 {
			return 0, 0, 0, 0, nil, false
		}
		if s[tzPos-1] == '-' {
			secs = -secs
		}
		if secs == 0 && tc[3] == 0 {
			return hh, mm, ss, us, time.UTC, true
		}
		return hh, mm, ss, us, time.FixedZone("", secs), true
	}
	return hh, mm, ss, us, nil, true
}

// Strftime implements the handful of strftime directives the service uses (%Y %m %d %H %M %S).
func Strftime(t time.Time, format string) string {
	r := strings.NewReplacer("%Y", fmt.Sprintf("%04d", t.Year()), "%m", fmt.Sprintf("%02d", int(t.Month())),
		"%d", fmt.Sprintf("%02d", t.Day()), "%H", fmt.Sprintf("%02d", t.Hour()),
		"%M", fmt.Sprintf("%02d", t.Minute()), "%S", fmt.Sprintf("%02d", t.Second()))
	return r.Replace(format)
}

// TimedeltaDays is (a - b).days: the floor of the difference in days.
func TimedeltaDays(a, b time.Time) int64 {
	d := a.Sub(b).Truncate(time.Microsecond)
	days := int64(d / (24 * time.Hour))
	if d < 0 && d%(24*time.Hour) != 0 {
		days--
	}
	return days
}
