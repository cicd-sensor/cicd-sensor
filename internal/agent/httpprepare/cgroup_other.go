//go:build !linux

package httpprepare

import "os"

import "github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"

func openProcessMembership(string) (*os.File, error) { return nil, kernelio.ErrNotSupported }
