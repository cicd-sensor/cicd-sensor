// Copyright 2022-2025 The Connect Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelconnect

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/semconv/v1.43.0/rpcconv"
)

const (
	serverKey   = "server"
	clientKey   = "client"
	requestKey  = "request"
	responseKey = "response"
)

type instruments struct {
	duration metric.Float64Histogram
}

// createInstruments creates the metrics for the interceptor. The histogram
// is not built with rpcconv's constructors: they append their own bucket
// boundaries after the caller's options, so callers could never override them.
func createInstruments(meter metric.Meter, side string, options []metric.Float64HistogramOption) (instruments, error) {
	var name, unit, description string
	switch side {
	case serverKey:
		inst := rpcconv.ServerCallDuration{}
		name, unit, description = inst.Name(), inst.Unit(), inst.Description()
	case clientKey:
		inst := rpcconv.ClientCallDuration{}
		name, unit, description = inst.Name(), inst.Unit(), inst.Description()
	default:
		return instruments{}, fmt.Errorf("unknown interceptor side %q", side)
	}
	histogramOptions := make([]metric.Float64HistogramOption, 0, 3+len(options))
	histogramOptions = append(histogramOptions,
		metric.WithUnit(unit),
		metric.WithDescription(description),
		// Spec-recommended buckets; caller options follow and win.
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10),
	)
	histogramOptions = append(histogramOptions, options...)
	duration, err := meter.Float64Histogram(name, histogramOptions...)
	if err != nil {
		return instruments{}, err
	}
	return instruments{duration: duration}, nil
}
