//go:build linux

package kernelio

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestStagingOperationsValidateBasename(t *testing.T) {
	t.Parallel()

	kernelIO := &LinuxKernelIO{}
	oversized := strings.Repeat("a", StagingKeyLen+1)

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "put staging oversized basename",
			run: func() error {
				return kernelIO.PutCgroupBasenameInStagingMap(context.Background(), oversized)
			},
		},
		{
			name: "delete staging oversized basename",
			run: func() error {
				return kernelIO.DeleteCgroupBasenamesFromStagingMap(context.Background(), []string{oversized})
			},
		},
		{
			name: "lookup staging oversized basename",
			run: func() error {
				_, err := kernelIO.TestOnlyLookupCgroupBasenameInStagingMap(context.Background(), oversized)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.run(); err == nil {
				t.Fatalf("%s returned nil error", tt.name)
			}
		})
	}
}

func TestPluralDeleteOperationsAcceptEmptyInput(t *testing.T) {
	t.Parallel()

	kernelIO := &LinuxKernelIO{}
	if err := kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(context.Background(), nil); err != nil {
		t.Fatalf("DeleteCgroupIDsFromTrackedCgroupsMap nil input: %v", err)
	}
	if err := kernelIO.DeleteCgroupBasenamesFromStagingMap(context.Background(), nil); err != nil {
		t.Fatalf("DeleteCgroupBasenamesFromStagingMap nil input: %v", err)
	}
}

func TestFixedStagingMapKeyPadsBasename(t *testing.T) {
	t.Parallel()

	key, err := fixedStagingMapKey([]byte("docker-abc.scope"))
	if err != nil {
		t.Fatalf("fixedStagingMapKey returned error: %v", err)
	}
	if len(key) != StagingKeyLen {
		t.Fatalf("fixed key length: got %d, want %d", len(key), StagingKeyLen)
	}
	if got := string(key[:len("docker-abc.scope")]); got != "docker-abc.scope" {
		t.Fatalf("fixed key prefix: got %q", got)
	}
	if tail := key[len("docker-abc.scope"):]; !bytes.Equal(tail, make([]byte, len(tail))) {
		t.Fatalf("fixed key tail is not zero-padded")
	}
}

func TestFixedStagingMapKeyRejectsOversizedBasename(t *testing.T) {
	t.Parallel()

	if _, err := fixedStagingMapKey([]byte(strings.Repeat("a", StagingKeyLen+1))); err == nil {
		t.Fatalf("expected oversized staging key error")
	}
}

func TestFixedStagingMapKeyRejectsPathLikeBasename(t *testing.T) {
	t.Parallel()

	if _, err := fixedStagingMapKey([]byte("/kubepods.slice/docker-abc.scope")); err == nil {
		t.Fatalf("expected path-like staging key error")
	}
}

func TestFixedStagingMapValueDefaultsToZeroPayload(t *testing.T) {
	t.Parallel()

	value, err := fixedStagingMapValue(nil)
	if err != nil {
		t.Fatalf("fixedStagingMapValue returned error: %v", err)
	}
	if len(value) != StagingValueLen {
		t.Fatalf("fixed value length: got %d, want %d", len(value), StagingValueLen)
	}
	if !bytes.Equal(value, make([]byte, StagingValueLen)) {
		t.Fatalf("fixed value is not zero payload")
	}
}

func TestFixedStagingMapValueRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	if _, err := fixedStagingMapValue(make([]byte, StagingValueLen+1)); err == nil {
		t.Fatalf("expected oversized staging value error")
	}
}
