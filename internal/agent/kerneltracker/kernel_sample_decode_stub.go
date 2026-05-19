//go:build !linux

package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"

func decodeKernelSample(sample kernelio.KernelSample) (decodedKernelSample, error) {
	_ = sample
	return nil, kernelio.ErrNotSupported
}
