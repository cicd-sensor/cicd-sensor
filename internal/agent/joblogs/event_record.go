package joblogs

import (
	"slices"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
)

func sanitizedLogEventRecord(event jobevent.EventRecord) *logv1.EventRecord {
	event.Process = jobevent.RedactProcessSummaryForOutput(event.Process)
	return logEventRecord(event)
}

func logEventRecord(event jobevent.EventRecord) *logv1.EventRecord {
	out := &logv1.EventRecord{
		Id:      event.ID,
		Type:    string(event.EventType),
		Tags:    logEventTags(event.Tags),
		Process: logProcessSummary(event.Process),
	}
	switch event.EventType {
	case jobevent.ProcessExec:
		out.ProcessExec = &logv1.ProcessExecPayload{IsMemfd: payloadBool(event.Payload, "is_memfd")}
	case jobevent.NetworkConnect:
		remoteIP, _ := event.Payload["remote_ip"].(string)
		protocol, _ := event.Payload["protocol"].(string)
		family, _ := event.Payload["family"].(string)
		out.NetworkConnect = &logv1.NetworkConnectPayload{
			RemoteIp:   remoteIP,
			RemotePort: uint32(payloadInt64(event.Payload, "remote_port")),
			Protocol:   protocol,
			Family:     family,
		}
	case jobevent.UnixSocketConnect:
		path, _ := event.Payload["path"].(string)
		socketType, _ := event.Payload["socket_type"].(string)
		out.UnixSocketConnect = &logv1.UnixSocketConnectPayload{
			Path:       path,
			SocketType: socketType,
			IsAbstract: payloadBool(event.Payload, "is_abstract"),
		}
	case jobevent.FileOpen:
		path, _ := event.Payload["path"].(string)
		out.FileOpen = &logv1.FileOpenPayload{
			Path:    path,
			IsWrite: payloadBool(event.Payload, "is_write"),
			IsRead:  payloadBool(event.Payload, "is_read"),
			Flags:   uint64(payloadInt64(event.Payload, "flags")),
		}
	case jobevent.FileRemove:
		path, _ := event.Payload["path"].(string)
		out.FileRemove = &logv1.FileRemovePayload{
			Path:     path,
			IsFolder: payloadBool(event.Payload, "is_folder"),
		}
	case jobevent.FileMove:
		fromPath, _ := event.Payload["from_path"].(string)
		toPath, _ := event.Payload["to_path"].(string)
		out.FileMove = &logv1.FileMovePayload{
			FromPath: fromPath,
			ToPath:   toPath,
		}
	case jobevent.FileLink:
		createdPath, _ := event.Payload["created_path"].(string)
		existingPath, _ := event.Payload["existing_path"].(string)
		out.FileLink = &logv1.FileLinkPayload{
			CreatedPath:  createdPath,
			ExistingPath: existingPath,
			IsHardlink:   payloadBool(event.Payload, "is_hardlink"),
			IsSymlink:    payloadBool(event.Payload, "is_symlink"),
		}
	case jobevent.Domain:
		name, _ := event.Payload["domain"].(string)
		source, _ := event.Payload["source"].(string)
		out.Domain = &logv1.DomainPayload{
			Name:   name,
			Source: source,
		}
	}
	return out
}

func logProcessSummary(process jobevent.ProcessSummary) *logv1.ProcessSummary {
	out := &logv1.ProcessSummary{
		Pid:      process.PID,
		ExecPath: process.ExecPath,
		Argv:     slices.Clone(process.Argv),
	}
	if len(process.Ancestors) > 0 {
		out.Ancestors = make([]*logv1.AncestorProcess, 0, len(process.Ancestors))
		for _, ancestor := range process.Ancestors {
			out.Ancestors = append(out.Ancestors, &logv1.AncestorProcess{
				ExecPath: ancestor.ExecPath,
				Argv:     slices.Clone(ancestor.Argv),
			})
		}
	}
	return out
}

func logEventTags(tags map[string]string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for k, v := range tags {
		out = append(out, k+":"+v)
	}
	slices.Sort(out)
	return out
}

func payloadBool(payload map[string]any, key string) bool {
	value, ok := payload[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		return false
	}
}

func payloadInt64(payload map[string]any, key string) int64 {
	value, ok := payload[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint64:
		if typed > uint64(^uint64(0)>>1) {
			return 0
		}
		return int64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}
