//go:build linux

package kernelio

import "log/slog"

func New(logger *slog.Logger, config Config) (KernelIO, error) {
	return NewLinux(logger, config)
}
