package kerneltracker

import "time"

// bootTimeOffsetNs normalizes kernel boot-relative nanoseconds to Unix time.
var bootTimeOffsetNs int64

// bootNsToUTC converts one kernel boot-relative timestamp to UTC.
func bootNsToUTC(tsNs uint64) time.Time {
	return time.Unix(0, int64(tsNs)+bootTimeOffsetNs).UTC()
}
