package kerneltracker

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// processIdentity is the KernelTracker-internal stable identifier for one process
// instance. PID alone is not sufficient because Linux reuses PIDs.
type processIdentity struct {
	PID           int32
	StartBoottime uint64
}

type processState uint8

const (
	processStateRunning processState = iota
	processStateExited
)

const maxAncestorDepth = 16

// processExitGracePeriod keeps exited processes briefly for late event enrichment.
const processExitGracePeriod = 10 * time.Second

const processPurgeInterval = 10 * time.Second

type ancestorSnapshot = jobevent.AncestorProcess

// processNode is the Fat Node for process enrichment. Each node keeps the
// full ancestor snapshots captured at fork time so lineage lookups stay O(1).
type processNode struct {
	Identity      processIdentity
	State         processState
	ExitTimestamp time.Time
	ExecPath      string
	Argv          []string
	Ancestors     [maxAncestorDepth]ancestorSnapshot
	AncestorCount uint8
}

type jobProcessState struct {
	nodesByIdentity map[processIdentity]*processNode
	exitedQueue     []processIdentity
}

func newJobProcessState() *jobProcessState {
	return &jobProcessState{
		nodesByIdentity: make(map[processIdentity]*processNode),
	}
}

func (s *jobTrackingState) recordFork(jobID jobcontext.JobIdentity, child, parent processIdentity) bool {
	processes := s.processesByJob[jobID]
	if processes == nil {
		return false
	}

	node := &processNode{
		Identity: child,
		State:    processStateRunning,
	}
	if parentNode := processes.nodesByIdentity[parent]; parentNode != nil {
		node.ExecPath = parentNode.ExecPath
		node.Argv = slices.Clone(parentNode.Argv)

		fit := int(parentNode.AncestorCount)
		if fit > maxAncestorDepth-1 {
			fit = maxAncestorDepth - 1
		}
		copy(node.Ancestors[1:1+fit], parentNode.Ancestors[:fit])
		node.Ancestors[0] = ancestorSnapshot{
			ExecPath: parentNode.ExecPath,
			Argv:     parentNode.Argv,
		}
		node.AncestorCount = uint8(fit + 1)
	}

	processes.nodesByIdentity[child] = node
	return true
}

func (s *jobTrackingState) recordExec(jobID jobcontext.JobIdentity, identity processIdentity, execPath string, argvBlob []byte, argc uint32) (jobevent.ProcessSummary, bool) {
	processes := s.processesByJob[jobID]
	if processes == nil {
		return jobevent.ProcessSummary{}, false
	}

	node := processes.nodesByIdentity[identity]
	if node == nil {
		node = &processNode{
			Identity: identity,
			State:    processStateRunning,
		}
		processes.nodesByIdentity[identity] = node
	}

	node.ExecPath = execPath
	node.Argv = splitArgv(argvBlob, int(argc))
	node.State = processStateRunning

	return processSummaryFromNode(node), true
}

func (s *jobTrackingState) recordExit(jobID jobcontext.JobIdentity, identity processIdentity, timestamp time.Time) {
	processes := s.processesByJob[jobID]
	if processes == nil {
		return
	}

	node := processes.nodesByIdentity[identity]
	if node == nil {
		return
	}
	if node.State == processStateExited {
		return
	}

	node.State = processStateExited
	node.ExitTimestamp = timestamp
	processes.exitedQueue = append(processes.exitedQueue, identity)
}

func (s *jobTrackingState) lookupProcessSummary(jobID jobcontext.JobIdentity, identity processIdentity) jobevent.ProcessSummary {
	processes := s.processesByJob[jobID]
	if processes == nil {
		return processSummaryFromIdentity(identity)
	}
	node := processes.nodesByIdentity[identity]
	if node == nil {
		// Miss covers pre-existing processes alive before agent attach (their
		// fork/exec was never observed). Best-effort fill from /proc; cache
		// so subsequent events for the same identity hit the normal path.
		node = backfillProcessNode(identity)
		if node == nil {
			return processSummaryFromIdentity(identity)
		}
		processes.nodesByIdentity[identity] = node
	}
	return processSummaryFromNode(node)
}

func (s *jobTrackingState) purgeExitedProcesses(now time.Time) {
	for _, processes := range s.processesByJob {
		if processes == nil || len(processes.exitedQueue) == 0 {
			continue
		}

		purged := 0
		for purged < len(processes.exitedQueue) {
			identity := processes.exitedQueue[purged]
			node := processes.nodesByIdentity[identity]
			if node.ExitTimestamp.Add(processExitGracePeriod).After(now) {
				break
			}

			delete(processes.nodesByIdentity, identity)
			purged++
		}

		if purged > 0 {
			processes.exitedQueue = processes.exitedQueue[purged:]
		}
	}
}

// startProcessPurgeTicker queues purge as an job tracking input so process cleanup
// stays serialized with kernel events and API commands.
func (engine *KernelTracker) startProcessPurgeTicker(ctx context.Context) func() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(processPurgeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case engine.inputCh <- commandPurgeExitedProcesses{}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return wg.Wait
}

func processSummaryFromNode(node *processNode) jobevent.ProcessSummary {
	var ancestors []jobevent.AncestorProcess
	if node.AncestorCount > 0 {
		ancestors = slices.Clone(node.Ancestors[:node.AncestorCount])
	}
	return jobevent.ProcessSummary{
		PID:           node.Identity.PID,
		StartBoottime: node.Identity.StartBoottime,
		ExecPath:      node.ExecPath,
		Argv:          node.Argv,
		Ancestors:     ancestors,
	}
}

func processSummaryFromIdentity(identity processIdentity) jobevent.ProcessSummary {
	return jobevent.ProcessSummary{
		PID:           identity.PID,
		StartBoottime: identity.StartBoottime,
	}
}

func splitArgv(blob []byte, argc int) []string {
	if argc <= 0 {
		return nil
	}

	argv := make([]string, 0, argc)
	cursor := 0
	for index := 0; index < argc; index++ {
		if cursor >= len(blob) {
			break
		}

		nul := bytes.IndexByte(blob[cursor:], 0)
		if nul == -1 {
			argv = append(argv, string(blob[cursor:]))
			break
		}

		argv = append(argv, string(blob[cursor:cursor+nul]))
		cursor += nul + 1
	}
	return argv
}
