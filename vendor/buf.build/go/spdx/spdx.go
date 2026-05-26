// Copyright 2024 Buf Technologies, Inc.
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

// Package spdx contains license information from SPDX.
//
// See https://spdx.org/licenses.
package spdx

import (
	"sort"
	"strings"
)

// License is a SPDX license.
type License struct {
	// ID is the SPDX ID of the license.
	ID string `json:"licenseId,omitempty"`
	// Name is the full license name.
	Name string `json:"name,omitempty"`
	// Reference is the URL that contains the reference documentation for the license.
	Reference string `json:"reference,omitempty"`
	// ReferenceNumber is the license reference number.
	ReferenceNumber int `json:"referenceNumber,omitempty"`
	// DetsilsURL is the URL that contains extra details on the license.
	DetailsURL string `json:"detailsUrl,omitempty"`
	// Deprecated indicates whether the license ID is deprecated.
	Deprecated bool `json:"isDeprecatedLicenceId,omitempty"`
	// SellAlso are additional URLs where the licensecan be found in use.
	SeeAlso []string `json:"seeAlso,omitempty"`
	// OSIApproved indicates whether the complies with the Open Source Definition and is approved
	// by the Open Source Initiative.
	OSIApproved bool `json:"isOsiApproved,omitempty"`
}

// LicenseForID returns the License for the ID.
//
// The input ID is case-insensitive, that is any casing of the ID will
// result in the correct License.
func LicenseForID(id string) (License, bool) {
	license, ok := lowercaseIDToLicense[strings.ToLower(id)]
	return license, ok
}

// AllLicenses returns a slice of all Licenses.
//
// This slice will be sorted by License ID.
func AllLicenses() []License {
	licenses := make([]License, 0, len(lowercaseIDToLicense))
	for _, license := range lowercaseIDToLicense {
		licenses = append(licenses, license)
	}
	sort.Slice(
		licenses,
		func(i int, j int) bool {
			return licenses[i].ID < licenses[j].ID
		},
	)
	return licenses
}
