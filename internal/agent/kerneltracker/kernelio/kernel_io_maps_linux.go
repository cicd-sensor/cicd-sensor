//go:build linux

package kernelio

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

func (kernelIO *LinuxKernelIO) PutCgroupIDInTrackedCgroupsMap(ctx context.Context, cgroupID uint64) error {
	_ = ctx
	kernelIO.trackingMu.Lock()
	defer kernelIO.trackingMu.Unlock()
	kernelIO.trackingSequence.Add(1)
	defer kernelIO.trackingSequence.Add(1)
	owner := kernelIO.nextHTTPOwner.Add(1)
	if owner == 0 {
		return errors.New("HTTP owner counter exhausted")
	}
	if err := kernelIO.objs.TrackedCgroups.Update(cgroupID, owner, ebpf.UpdateNoExist); err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		return fmt.Errorf("put cgroup id %d in tracked_cgroups map: %w", cgroupID, err)
	}
	return nil
}

func (kernelIO *LinuxKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(ctx context.Context, cgroupIDs []uint64) error {
	_ = ctx
	kernelIO.trackingMu.Lock()
	defer kernelIO.trackingMu.Unlock()
	kernelIO.trackingSequence.Add(1)
	defer kernelIO.trackingSequence.Add(1)
	defer kernelIO.QueueHTTPUprobeReconciliation()
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
	owner := kernelIO.nextHTTPOwner.Add(1)
	if owner == 0 {
		return errors.New("HTTP owner counter exhausted")
	}
	value, err := fixedStagingMapValue(binary.LittleEndian.AppendUint64(nil, owner))
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
	var value uint64
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
	// Preserve the fixed staging ABI, with the HTTP owner in its first eight bytes.
	fixed := make([]byte, StagingValueLen)
	copy(fixed, value)
	return fixed, nil
}

// TestOnlyOpenSSLProgram returns the OpenSSL uprobe entry program so
// integration tests can attach it directly to a libssl inode. Not for
// production use — production attaches via OpenSSL uprobe discovery.
func (kernelIO *LinuxKernelIO) TestOnlyOpenSSLProgram() *ebpf.Program {
	return kernelIO.objs.HandleSslWrite
}

// httpOwner reads only the kernel tracking decision, not a container pathname.
func (kernelIO *LinuxKernelIO) httpOwner(cgroupID uint64) uint64 {
	var owner uint64
	if kernelIO.objs.TrackedCgroups == nil || kernelIO.objs.TrackedCgroups.Lookup(cgroupID, &owner) != nil {
		return 0
	}
	return owner
}

type cgroupTrackingStamp struct{ Writers, Sequence uint64 }

func (kernelIO *LinuxKernelIO) httpOwners() (map[uint64]struct{}, error) {
	// Never hold the tracking reactor behind a worker scan. Odd generations
	// mean a userspace update is in progress; a changed generation invalidates
	// the snapshot, just like the BPF writer stamp below.
	generation := kernelIO.trackingSequence.Load()
	if generation&1 != 0 {
		return nil, errors.New("userspace tracking changing")
	}
	var before, after cgroupTrackingStamp
	if err := kernelIO.objs.CgroupTrackingChanges.Lookup(uint32(0), &before); err != nil {
		return nil, err
	}
	if before.Writers != 0 {
		return nil, errors.New("cgroup tracking changing")
	}
	owners := make(map[uint64]struct{})
	var id, owner uint64
	it := kernelIO.objs.TrackedCgroups.Iterate()
	for it.Next(&id, &owner) {
		if owner != 0 {
			owners[owner] = struct{}{}
		}
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	if err := kernelIO.objs.CgroupTrackingChanges.Lookup(uint32(0), &after); err != nil {
		return nil, err
	}
	if after.Writers != 0 || before.Sequence != after.Sequence || kernelIO.trackingSequence.Load() != generation {
		return nil, errors.New("cgroup tracking changed during scan")
	}
	return owners, nil
}

// TestOnlyHTTPOwner exposes the attach cookie for direct-program integration tests.
func (kernelIO *LinuxKernelIO) TestOnlyHTTPOwner(cgroupID uint64) uint64 {
	return kernelIO.httpOwner(cgroupID)
}
