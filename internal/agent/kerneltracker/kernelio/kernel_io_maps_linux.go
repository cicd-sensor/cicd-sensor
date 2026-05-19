//go:build linux

package kernelio

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

func (kernelIO *LinuxKernelIO) PutCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64) error {
	_ = ctx
	if err := kernelIO.objs.TrackedCgroups.Update(cgroupID, uint8(1), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("put cgroup id %d in tracked_cgroups map: %w", cgroupID, err)
	}
	return nil
}

func (kernelIO *LinuxKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(ctx context.Context, cgroupIDs []uint64) error {
	_ = ctx
	for _, cgroupID := range cgroupIDs {
		if err := kernelIO.objs.TrackedCgroups.Delete(cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete cgroup id %d from tracked_cgroups map: %w", cgroupID, err)
		}
	}
	return nil
}

func (kernelIO *LinuxKernelIO) PutCgroupBasenameInStagingMap(ctx context.Context, basename string) error {
	_ = ctx
	key, err := fixedStagingMapKey([]byte(basename))
	if err != nil {
		return err
	}
	value, err := fixedStagingMapValue(nil)
	if err != nil {
		return err
	}
	if err := kernelIO.objs.StagingMap.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("put cgroup basename %q in staging_map: %w", basename, err)
	}
	return nil
}

func (kernelIO *LinuxKernelIO) DeleteCgroupBasenamesFromStagingMap(ctx context.Context, basenames []string) error {
	_ = ctx
	for _, basename := range basenames {
		key, err := fixedStagingMapKey([]byte(basename))
		if err != nil {
			return err
		}
		// Kernel cgroup_mkdir promotion may have already consumed this entry.
		if err := kernelIO.objs.StagingMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete cgroup basename %q from staging_map: %w", basename, err)
		}
	}
	return nil
}

func (kernelIO *LinuxKernelIO) TestOnlyLookupCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64) (bool, error) {
	_ = ctx
	var value uint8
	err := kernelIO.objs.TrackedCgroups.Lookup(cgroupID, &value)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup cgroup id %d in tracked_cgroups map: %w", cgroupID, err)
	}
	return true, nil
}

func (kernelIO *LinuxKernelIO) TestOnlyLookupCgroupBasenameInStagingMap(ctx context.Context, basename string) (bool, error) {
	_ = ctx
	key, err := fixedStagingMapKey([]byte(basename))
	if err != nil {
		return false, err
	}
	var value [StagingValueLen]byte
	err = kernelIO.objs.StagingMap.Lookup(key, &value)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup cgroup basename %q in staging_map: %w", basename, err)
	}
	return true, nil
}

func fixedStagingMapKey(key []byte) ([]byte, error) {
	if len(key) > StagingKeyLen {
		return nil, fmt.Errorf("staging_map key must be at most %d bytes, got %d", StagingKeyLen, len(key))
	}
	if bytes.IndexByte(key, '/') >= 0 {
		return nil, fmt.Errorf("staging_map key must be a cgroup basename, got %q", string(key))
	}
	// staging_map uses char[STAGING_KEY_LEN], so short basenames must be zero-padded.
	fixed := make([]byte, StagingKeyLen)
	copy(fixed, key)
	return fixed, nil
}

func fixedStagingMapValue(value []byte) ([]byte, error) {
	if len(value) > StagingValueLen {
		return nil, fmt.Errorf("staging_map value must be at most %d bytes, got %d", StagingValueLen, len(value))
	}
	// The current BPF hook only checks lookup hits; zero value is the intended v1 payload.
	fixed := make([]byte, StagingValueLen)
	copy(fixed, value)
	return fixed, nil
}
