//go:build linux

package kerneltracker

import "golang.org/x/sys/unix"

// init captures the CLOCK_REALTIME - CLOCK_MONOTONIC delta once at
// package load. bpf_ktime_get_ns() in the kernel returns a
// CLOCK_MONOTONIC value, so adding this offset to it yields a Unix
// nanosecond timestamp. Computing it once avoids a per-sample syscall
// on the sample hot path.
//
// The offset is wall-clock sensitive: if the system clock is adjusted
// after agent start (e.g. NTP step), reported timestamps will drift.
// Ephemeral CI hosts never step far, so a single captured offset is
// acceptable for attestation; a long-lived agent could periodically
// refresh this if drift becomes a concern.
func init() {
	var realTs, monoTs unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realTs); err != nil {
		return
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monoTs); err != nil {
		return
	}
	bootTimeOffsetNs = realTs.Nano() - monoTs.Nano()
}
