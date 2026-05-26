// Copyright 2024-2025 Buf Technologies, Inc.
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

package info

import (
	"net/url"

	"buf.build/go/spdx"
)

// Spec is the spec for the information about a plugin.
type Spec struct {
	// Documentation contains the documentation of the plugin.
	//
	// Optional.
	Documentation string
	// SPDXLicenseID is the SDPX ID of the License.
	//
	// Optional.
	//
	// This must be present in the SPDX license list.
	// https://spdx.org/licenses
	//
	// This can be specified in any case. This package will translate this into
	// proper casing.
	SPDXLicenseID string
	// LicenseText is the raw text of the License.
	//
	// Optional.
	//
	// Zero or one of LicenseText and LicenseURL must be set.
	LicenseText string
	// LicenseURL is the URL that contains the License.
	//
	// Optional.
	//
	// Zero or one of LicenseText and LicenseURL must be set.
	// Must be absolute if set.
	LicenseURL string
}

// ValidateSpec validates all values on a Spec.
func ValidateSpec(spec *Spec) error {
	if spec.SPDXLicenseID != "" {
		if _, ok := spdx.LicenseForID(spec.SPDXLicenseID); !ok {
			return newValidateSpecErrorf("invalid SPDXLicenseID: %q", spec.SPDXLicenseID)
		}
	}
	if spec.LicenseText != "" && spec.LicenseURL != "" {
		return newValidateSpecError("only one of LicenseText and LicenseURL can be set")
	}
	if spec.LicenseURL != "" {
		if err := validateSpecAbsoluteURL(spec.LicenseURL); err != nil {
			return err
		}
	}
	return nil
}

// *** PRIVATE ***

func validateSpecAbsoluteURL(urlString string) error {
	url, err := url.Parse(urlString)
	if err != nil {
		return newValidateSpecErrorf("invalid URL: %w", err)
	}
	if url.Host == "" {
		return newValidateSpecErrorf("invalid URL: must be absolute: %q", urlString)
	}
	return nil
}
