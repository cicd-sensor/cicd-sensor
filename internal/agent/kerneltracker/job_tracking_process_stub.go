//go:build !linux

package kerneltracker

// backfillProcessNode is a no-op stub for non-Linux developer builds.
func backfillProcessNode(identity processIdentity) *processNode {
	_ = identity
	return nil
}
