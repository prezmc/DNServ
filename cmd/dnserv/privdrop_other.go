//go:build !linux

package main

import "log/slog"

func dropRoot(*slog.Logger, ...string) {}
