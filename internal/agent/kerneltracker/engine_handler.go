package kerneltracker

// handleEngineInput mutates loop-owned jobTrackingState and returns effects.
func handleEngineInput(state *jobTrackingState, input engineInput) []engineEffect {
	switch value := input.(type) {
	case commandRegisterJob:
		return handleRegisterJob(state, value)
	case commandBindCgroup:
		return handleBindCgroup(state, value)
	case commandRemoveJob:
		return handleRemoveJob(state, value)
	case commandStageCgroupBasename:
		return handleStageCgroupBasename(state, value)
	case commandFindJobForCgroup:
		jobID, found := state.jobForCgroup(value.CgroupID)
		return []engineEffect{replyJobForCgroup{
			Reply: value.Reply,
			Result: JobForCgroupResult{
				JobID: jobID,
				Found: found,
			},
		}}
	case forkSample:
		return handleForkSample(state, value)
	case execSample:
		return handleExecSample(state, value)
	case exitSample:
		return handleExitSample(state, value)
	case commandPurgeExpiredTrackingState:
		return handlePurgeTick(state)
	case commandReconcileCgroupLiveness:
		return handleCgroupLivenessReconciliation(state, value)
	case cgroupMkdirSample:
		return handleCgroupMkdirSample(state, value)
	case cgroupAttachSample:
		return handleCgroupAttachSample(state, value)
	case cgroupRmdirSample:
		return handleCgroupRmdirSample(state, value)
	case netConnectV4Sample:
		return handleNetConnectV4Sample(state, value)
	case netConnectV6Sample:
		return handleNetConnectV6Sample(state, value)
	case fileOpenSample:
		return handleFileOpenSample(state, value)
	case fileRemoveSample:
		return handleFileRemoveSample(state, value)
	case fileMoveSample:
		return handleFileMoveSample(state, value)
	case fileLinkSample:
		return handleFileLinkSample(state, value)
	case dnsSample:
		return handleDNSSample(state, value)
	case unixSocketConnectSample:
		return handleUnixSocketConnectSample(state, value)
	default:
		return nil
	}
}
