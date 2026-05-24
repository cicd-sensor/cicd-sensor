package report

// Renders the in-toto runtime-trace v0.1 predicate. Wire schema is in
// proto/cicd_sensor/attestation/v1alpha1/predicate.proto (source of truth).

import (
	"io"
	"slices"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	attestationv1alpha1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/attestation/v1alpha1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

var attestationJSONMarshal = protojson.MarshalOptions{Indent: "  "}

func AttestationPredicate(log resultdoc.JobEventSummaryForReport) *attestationv1alpha1.Predicate {
	return &attestationv1alpha1.Predicate{
		MonitorLog: &attestationv1alpha1.MonitorLog{
			Network:    networkIPs(log.NetworkConnections),
			Detections: ruleHitProtos(log.Hits),
			Domains:    domainNames(log.DomainObservations),
			Result:     proto.String(log.ResultSummary.Result),
			Job:        protoconv.ToAttestationJob(log.JobIdentity, log.Metadata),
		},
	}
}

// Drops collect/unknown actions: predicate records policy outcomes only.
func ruleHitProtos(hits []resultdoc.HitRecord) []*attestationv1alpha1.RuleHitSummary {
	out := make([]*attestationv1alpha1.RuleHitSummary, 0, len(hits))
	for _, h := range hits {
		if h.Action != string(rule.RuleActionDetect) && h.Action != string(rule.RuleActionTerminate) {
			continue
		}
		out = append(out, &attestationv1alpha1.RuleHitSummary{
			RulesetId:       proto.String(h.RulesetID),
			RuleId:          proto.String(h.RuleID),
			RulesetRevision: proto.String(h.RulesetRevision),
			Action:          proto.String(h.Action),
			Count:           proto.Uint32(uint32(h.HitCount)),
		})
	}
	return out
}

func networkIPs(records []resultdoc.NetworkConnection) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		if r.RemoteIP != "" {
			out = append(out, r.RemoteIP)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func domainNames(records []resultdoc.DomainObservation) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		if r.Domain != "" {
			out = append(out, r.Domain)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func RenderAttestation(w io.Writer, log *resultdoc.JobEventSummaryForReport) error {
	body, err := attestationJSONMarshal.Marshal(AttestationPredicate(*log))
	if err != nil {
		return err
	}
	body = append(body, '\n')
	_, err = w.Write(body)
	return err
}
