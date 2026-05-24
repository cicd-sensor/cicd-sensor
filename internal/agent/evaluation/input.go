package evaluation

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

func celInputEventFromRecord(event jobevent.EventRecord) celengine.CELInputEvent {
	input := celengine.CELInputEvent{
		Process: celProcessFromSummary(event.Process),
	}

	switch event.EventType {
	case jobevent.ProcessExec:
		input.IsMemfd = payloadBool(event.Payload, "is_memfd")
	case jobevent.NetworkConnect:
		input.RemoteIP = normalizedPayloadString(event.Payload, "remote_ip")
		input.RemotePort = payloadInt(event.Payload, "remote_port")
		input.Protocol = normalizedPayloadString(event.Payload, "protocol")
		input.Family = normalizedPayloadString(event.Payload, "family")
	case jobevent.FileOpen:
		input.Path = normalizedPayloadString(event.Payload, "path")
		input.IsWrite = payloadBool(event.Payload, "is_write")
		input.IsRead = payloadBool(event.Payload, "is_read")
		input.Flags = payloadInt(event.Payload, "flags")
	case jobevent.FileRemove:
		input.Path = normalizedPayloadString(event.Payload, "path")
		input.IsFolder = payloadBool(event.Payload, "is_folder")
	case jobevent.FileMove:
		input.FromPath = normalizedPayloadString(event.Payload, "from_path")
		input.ToPath = normalizedPayloadString(event.Payload, "to_path")
	case jobevent.FileLink:
		input.CreatedPath = normalizedPayloadString(event.Payload, "created_path")
		input.ExistingPath = normalizedPayloadString(event.Payload, "existing_path")
		input.IsHardlink = payloadBool(event.Payload, "is_hardlink")
		input.IsSymlink = payloadBool(event.Payload, "is_symlink")
	case jobevent.Domain:
		input.Domain = normalizedPayloadString(event.Payload, "domain")
		input.Source = normalizedPayloadString(event.Payload, "source")
	case jobevent.UnixSocketConnect:
		input.Path = normalizedPayloadString(event.Payload, "path")
		input.SocketType = normalizedPayloadString(event.Payload, "socket_type")
		input.IsAbstract = payloadBool(event.Payload, "is_abstract")
	}

	return input
}

func celProcessFromSummary(ps jobevent.ProcessSummary) celengine.CELProcess {
	var ancestors []celengine.CELAncestor
	if len(ps.Ancestors) > 0 {
		ancestors = make([]celengine.CELAncestor, len(ps.Ancestors))
		for i, anc := range ps.Ancestors {
			ancestors[i] = celengine.CELAncestor{
				ExecPath: rule.NormalizeString(anc.ExecPath),
				Argv:     normalizeStringSlice(anc.Argv),
			}
		}
	}
	return celengine.NewCELProcess(
		rule.NormalizeString(ps.ExecPath),
		normalizeStringSlice(ps.Argv),
		ancestors,
	)
}

func normalizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, rule.NormalizeString(value))
	}
	return out
}

func normalizedPayloadString(payload map[string]any, key string) string {
	value, ok := payload[key]
	if !ok {
		return ""
	}
	typed, ok := value.(string)
	if !ok {
		return ""
	}
	return rule.NormalizeString(typed)
}

func payloadInt(payload map[string]any, key string) int64 {
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
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func payloadBool(payload map[string]any, key string) bool {
	value, ok := payload[key]
	if !ok {
		return false
	}
	typed, ok := value.(bool)
	if !ok {
		return false
	}
	return typed
}
