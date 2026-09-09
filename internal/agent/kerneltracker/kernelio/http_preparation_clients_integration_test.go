//go:build linux && bpf_integration && http_client_integration

package kernelio

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"golang.org/x/sys/unix"
)

// This opt-in suite needs the four installed clients and writable cgroup/overlay
// mounts. Every run uses a distinct copied inode and the real preparation queue.
func TestHTTPPreparationClients(t *testing.T) {
	if os.Getenv("CICD_HTTP_CLIENT_E2E") != "1" {
		t.Skip("set CICD_HTTP_CLIENT_E2E=1 for privileged client fixtures")
	}
	curl := requireTestBinary(t, "curl")
	gh := requireTestBinary(t, "gh")
	glab := requireTestBinary(t, "glab")
	root := t.TempDir()
	lower := filepath.Join(root, "lower")
	for i := range 20 {
		for _, target := range []struct{ family, name, source string }{
			{"openssl", "libssl.so.3", findLibssl(t)}, {"nghttp2", "libnghttp2.so.14", findLibnghttp2(t)}, {"gh", "gh", gh}, {"glab", "glab", glab},
		} {
			copyPreparationFixture(t, target.source, filepath.Join(lower, target.family, fmt.Sprint(i), target.name))
		}
	}
	copyPreparationFixture(t, findLibssl(t), filepath.Join(lower, "fallback", "libssl.so.3"))
	merged := mountPreparationOverlay(t, lower)
	cgroup := fmt.Sprintf("/sys/fs/cgroup/cicd-http-preparation-test-%d", os.Getpid())
	if err := os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(cgroup); err != nil {
			t.Error(err)
		}
	})
	cgf, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer cgf.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(cgf.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	config := testLinuxConfig(t)
	config.EnableHTTPRequest = true
	ki, err := NewLinux(nil, config)
	if err != nil {
		t.Fatal(err)
	}
	defer ki.Close()
	if ki.httpUprobeWorker.control == nil {
		t.Fatal("backing control unavailable")
	}
	if err := ki.PutCgroupIDInTrackedCgroupsMap(t.Context(), stat.Ino); err != nil {
		t.Fatal(err)
	}
	events := make(chan bpfprog.BPFProgramHttpRequestSample, 256)
	if err := ki.StartKernelSampleLoop(t.Context(), func(_ context.Context, sample KernelSample) error {
		if len(sample) >= 4 && binary.LittleEndian.Uint32(sample[:4]) == 15 {
			var event bpfprog.BPFProgramHttpRequestSample
			if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &event); err != nil {
				return err
			}
			select {
			case events <- event:
			default:
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"login":"local","username":"local"}`))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	cert := filepath.Join(root, "cert.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	glabConfig := filepath.Join(root, "glab-config")
	if err := os.Mkdir(glabConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(glabConfig, "config.yml"), []byte("check_update: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + root, "SSL_CERT_FILE=" + cert, "GH_TOKEN=local-fixture-token", "GITLAB_TOKEN=local-fixture-token", "GITLAB_HOST=" + srv.URL, "GLAB_CONFIG_DIR=" + glabConfig, "GH_NO_UPDATE_NOTIFIER=1", "GLAB_SEND_TELEMETRY=false", "NO_COLOR=1"}
	t.Run("async_mapping_fallback", func(t *testing.T) {
		// No preparation request: the child maps another backing inode and waits
		// before HTTP. This proves eventual discovery, not a first-call guarantee.
		ready := filepath.Join(root, "fallback-ready")
		cmd := exec.CommandContext(t.Context(), requireTestBinary(t, "python3"), "-c", "import ssl,urllib.request,pathlib,sys; pathlib.Path(sys.argv[1]).touch(); sys.stdin.readline(); urllib.request.urlopen(sys.argv[2],context=ssl.create_default_context(cafile=sys.argv[3])).read()", ready, srv.URL+"/fallback", cert)
		cmd.Env = append(slices.Clone(env), "LD_LIBRARY_PATH="+filepath.Join(merged, "fallback"))
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgf.Fd())}
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("fallback child not ready")
			}
			time.Sleep(10 * time.Millisecond)
		}
		mapped, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", cmd.Process.Pid))
		if err != nil || !bytes.Contains(mapped, []byte(filepath.Join(merged, "fallback", "libssl.so.3"))) {
			t.Fatal("child did not map the unprepared library")
		}
		time.Sleep(500 * time.Millisecond)
		if _, err := input.Write([]byte("continue\n")); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		for {
			select {
			case ev := <-events:
				if ev.Tgid == int32(cmd.Process.Pid) && ev.CgroupId == stat.Ino && ev.Source == 1 {
					return
				}
			case <-timer.C:
				t.Fatal("mapping fallback failed to capture HTTP")
			}
		}
	})
	for _, tc := range []struct {
		name, file, path string
		args             []string
		source           uint8
	}{
		{"openssl", "libssl.so.3", "/probe", []string{"--http1.1", "-ksS", srv.URL + "/probe"}, 1},
		{"nghttp2", "libnghttp2.so.14", "/probe", []string{"--http2", "-ksS", srv.URL + "/probe"}, 2},
		{"gh", "gh", "/user", []string{"api", srv.URL + "/user"}, 3},
		{"glab", "glab", "/api/v4/user", []string{"api", "user"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captured := 0
			var latency []time.Duration
			for i := range 20 {
				dir := filepath.Join(merged, tc.name, fmt.Sprint(i))
				f, err := os.Open(filepath.Join(dir, tc.file))
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
				start := time.Now()
				err = ki.PrepareHTTPFiles(ctx, []*os.File{f}, "test-client")
				latency = append(latency, time.Since(start))
				cancel()
				if err != nil {
					t.Fatalf("prepare run %d: %v", i, err)
				}
				binaryPath := curl
				if tc.source == 3 {
					binaryPath = filepath.Join(dir, tc.file)
				}
				cmd := exec.CommandContext(t.Context(), binaryPath, tc.args...)
				cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgf.Fd())}
				cmd.Env = append(slices.Clone(env), "LD_LIBRARY_PATH="+dir)
				var output bytes.Buffer
				cmd.Stdout = &output
				cmd.Stderr = &output
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				pid := int32(cmd.Process.Pid)
				if err := cmd.Wait(); err != nil {
					t.Fatalf("client: %v %s", err, output.String())
				}
				hit := false
				timer := time.NewTimer(time.Second)
			wait:
				for {
					select {
					case ev := <-events:
						path := make([]byte, 0, len(ev.Path))
						for _, b := range ev.Path {
							if b == 0 {
								break
							}
							path = append(path, byte(b))
						}
						if ev.Tgid == pid && ev.CgroupId == stat.Ino && ev.Source == tc.source && string(path) == tc.path && ev.Method[0] == 'G' {
							hit = true
							break wait
						}
					case <-timer.C:
						break wait
					}
				}
				timer.Stop()
				if hit {
					captured++
				}
			}
			slices.Sort(latency)
			t.Logf("first_request=%d/20 preparation p50=%s p95=%s p99=%s", captured, latency[9], latency[18], latency[19])
			if captured != 20 {
				t.Errorf("first request captured %d/20", captured)
			}
		})
	}
}
