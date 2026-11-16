package analytics

import (
	"context"
	"database/sql"
	"net/netip"
	"strings"
	"time"

	"github.com/prezmc/dnserv/internal/querylog"
)

// Countries: with location data on, the writer notes which country each
// domain's answer pointed to (the first public address), one row per
// domain in name_cc. Analytics join on it to count lookups by country and
// to filter by one. It is the latest country seen, which for nearly every
// domain is the only one.
const countrySchema = `
CREATE TABLE IF NOT EXISTS name_cc (
	name TEXT PRIMARY KEY,
	cc   TEXT NOT NULL,
	t    INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS name_cc_cc ON name_cc (cc);
`

// TopCountries is the top list of countries answers pointed to.
const TopCountries = "countries"

// CountryFunc says which country an address is in ("" when unknown).
type CountryFunc func(netip.Addr) string

// SetCountry sets how answers' countries are found (nil: not noted).
func (s *Store) SetCountry(fn CountryFunc) { s.country.Store(&fn) }

func (s *Store) countryFn() CountryFunc {
	if p := s.country.Load(); p != nil {
		return *p
	}
	return nil
}

// countryOf is the country of the first address that has one.
func countryOf(fn CountryFunc, ips []netip.Addr) string {
	for _, a := range ips {
		if c := fn(a); c != "" {
			return c
		}
	}
	return ""
}

// validCountry accepts a two-letter upper-case code.
func validCountry(c string) bool {
	return len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z'
}

// countryDay is how often an unchanged row's time is refreshed, so the
// clean-up keeps domains still in use.
const countryDay = int64(24 * time.Hour / time.Microsecond)

// writeCountries notes each domain's country in a batch.
func (s *Store) writeCountries(tx *sql.Tx, batch []querylog.Entry) error {
	fn := s.countryFn()
	if fn == nil {
		return nil
	}
	type seen struct {
		cc string
		t  int64
	}
	names := map[string]seen{}
	for _, e := range batch {
		if len(e.Answer) == 0 {
			continue
		}
		ips, _ := answerOf(e.Answer)
		if cc := countryOf(fn, ips); cc != "" {
			names[e.Name] = seen{cc, e.Time.UnixMicro()}
		}
	}
	if len(names) == 0 {
		return nil
	}
	st, err := tx.Prepare(`INSERT INTO name_cc (name, cc, t) VALUES (?,?,?)
		ON CONFLICT (name) DO UPDATE SET cc = excluded.cc, t = excluded.t
		WHERE cc <> excluded.cc OR excluded.t > t + ?`)
	if err != nil {
		return err
	}
	defer st.Close()
	for n, v := range names {
		if _, err := st.Exec(n, v.cc, v.t, countryDay); err != nil {
			return err
		}
	}
	return nil
}

// BackfillCountries notes the country of domains already in the history
// (the individual queries kept), for location data turned on later. It
// runs in the background; only domains without a country yet are read.
func (s *Store) BackfillCountries() {
	fn := s.countryFn()
	if fn == nil {
		return
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		type row struct {
			name, cc string
			t        int64
		}
		var rows []row
		err := collect(context.Background(), s.db, `SELECT name, ips, MAX(t) FROM queries
			WHERE ips IS NOT NULL AND ips <> '' AND name NOT IN (SELECT name FROM name_cc) GROUP BY name`, nil, func(r *sql.Rows) error {
			var name, ips string
			var t int64
			if err := r.Scan(&name, &ips, &t); err != nil {
				return err
			}
			var addrs []netip.Addr
			for _, x := range strings.Split(ips, ",") {
				if a, err := netip.ParseAddr(strings.TrimSpace(x)); err == nil {
					addrs = append(addrs, a)
				}
			}
			if cc := countryOf(fn, addrs); cc != "" {
				rows = append(rows, row{name, cc, t})
			}
			return nil
		})
		if err != nil {
			s.log.Warn("noting countries of existing history failed", "err", err)
			return
		}
		for i := 0; i < len(rows); i += 500 {
			select {
			case <-s.stop:
				return
			default:
			}
			tx, err := s.db.Begin()
			if err != nil {
				return
			}
			for _, r := range rows[i:min(i+500, len(rows))] {
				if _, err := tx.Exec(`INSERT INTO name_cc (name, cc, t) VALUES (?,?,?) ON CONFLICT (name) DO NOTHING`, r.name, r.cc, r.t); err != nil {
					tx.Rollback()
					return
				}
			}
			if err := tx.Commit(); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond) // leave room for the writer
		}
		if len(rows) > 0 {
			s.log.Info("countries noted for existing history", "domains", len(rows))
		}
	}()
}

// ClearCountries forgets every domain's country (location data off).
func (s *Store) ClearCountries() error {
	_, err := s.db.Exec(`DELETE FROM name_cc`)
	return err
}

// topCountries counts answered lookups by the country they pointed to.
func (s *Store) topCountries(ctx context.Context, q *Query, res *Result) error {
	src, args, ok := s.source(q)
	if !ok {
		return nil
	}
	w, args := where(q, args)
	if w == "" {
		w = " WHERE result <> ?"
	} else {
		w += " AND result <> ?"
	}
	args = append(args, codeBlocked)
	return collect(ctx, s.db, `SELECT cc, SUM(n) FROM (SELECT s.client AS client, s.name AS name, s.result AS result, s.n AS n, c.cc AS cc FROM `+src+
		` AS s JOIN name_cc c ON c.name = s.name)`+w+` GROUP BY cc ORDER BY 2 DESC, 1 LIMIT ?`, append(args, q.Limit), func(r *sql.Rows) error {
		var row Row
		err := r.Scan(&row.Key, &row.Total)
		res.Rows = append(res.Rows, row)
		return err
	})
}

// flowCountries fills in each traffic map domain's country.
func (s *Store) flowCountries(ctx context.Context, f *Flow) error {
	if len(f.Names) == 0 {
		return nil
	}
	cc := map[string]string{}
	if err := collect(ctx, s.db, `SELECT name, cc FROM name_cc`, nil, func(r *sql.Rows) error {
		var n, c string
		err := r.Scan(&n, &c)
		cc[n] = c
		return err
	}); err != nil {
		return err
	}
	for i := range f.Names {
		f.Names[i].CC = cc[f.Names[i].Name]
	}
	return nil
}
