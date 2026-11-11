package analytics

import (
	"context"
	"database/sql"
)

// reach answers which devices looked up the given domains, how many of
// those lookups got an answer (were not blocked), and when; and, as a
// series, how many answered lookups of them there were per bucket. The
// security overview uses it for risky domains that got through.
func (s *Store) reach(ctx context.Context, q *Query, res *Result) error {
	src, args, ok := s.source(q)
	if !ok {
		return nil
	}
	w, args := where(q, args)
	cond := "name IN (" + placeholders(len(q.Names)) + ")"
	if w == "" {
		w = " WHERE " + cond
	} else {
		w += " AND " + cond
	}
	for _, n := range q.Names {
		args = append(args, n)
	}
	err := collect(ctx, s.db, `SELECT name, client, SUM(n), SUM(CASE WHEN result = ? THEN n ELSE 0 END),
		COALESCE(MAX(CASE WHEN result <> ? THEN sec END), 0) FROM `+src+w+` GROUP BY name, client`,
		append([]any{codeBlocked, codeBlocked}, args...), func(r *sql.Rows) error {
			var row Row
			err := r.Scan(&row.Key, &row.Client, &row.Total, &row.Blocked, &row.Last)
			res.Rows = append(res.Rows, row)
			return err
		})
	if err != nil {
		return err
	}
	return collect(ctx, s.db, `SELECT (sec + ?) / ? AS b, SUM(n) FROM `+src+w+` AND result <> ? GROUP BY b ORDER BY b`,
		append(append([]any{q.Offset, q.Step}, args...), codeBlocked), func(r *sql.Rows) error {
			var b, n int64
			if err := r.Scan(&b, &n); err != nil {
				return err
			}
			res.Series = append(res.Series, Point{T: b*q.Step - q.Offset, Counts: Counts{Total: n}})
			return nil
		})
}
