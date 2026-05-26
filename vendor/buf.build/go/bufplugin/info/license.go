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
	"errors"
	"fmt"
	"net/url"

	infov1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/info/v1"
	"buf.build/go/spdx"
)

// License contains license information about a plugin.
//
// A License will either have raw text or a URL that contains the License.
// Zero or one of these will be set.
type License interface {
	// SPDXLicenseID returns the SPDX license ID.
	//
	// Optional.
	//
	// Will be a valid SPDX license ID contained within https://spdx.org/licenses
	// if present.
	SPDXLicenseID() string
	// Text returns the raw text of the License.
	//
	// At most one of Text and URL will be set.
	Text() string
	// URL returns the URL that contains the License.
	//
	// At most one of Text and URL will be set.
	// Must be absolute if set.
	URL() *url.URL

	toProto() *infov1.License

	isLicense()
}

// *** PRIVATE ***

type license struct {
	spdxLicenseID string
	text          string
	url           *url.URL
}

func newLicense(
	// Case-insensitive.
	spdxLicenseID string,
	text string,
	url *url.URL,
) (*license, error) {
	if spdxLicenseID != "" {
		spdxLicense, ok := spdx.LicenseForID(spdxLicenseID)
		if !ok {
			return nil, fmt.Errorf("unknown SPDX license ID: %q", spdxLicenseID)
		}
		// Case-sensitive.
		spdxLicenseID = spdxLicense.ID
	}
	if text != "" && url != nil {
		return nil, errors.New("info.License: both text and url are present")
	}
	if url != nil && url.Host == "" {
		return nil, fmt.Errorf("url %v must be absolute", url)
	}
	return &license{
		spdxLicenseID: spdxLicenseID,
		text:          text,
		url:           url,
	}, nil
}

func (l *license) SPDXLicenseID() string {
	return l.spdxLicenseID
}

func (l *license) Text() string {
	return l.text
}

func (l *license) URL() *url.URL {
	return l.url
}

func (l *license) toProto() *infov1.License {
	if l == nil {
		return nil
	}
	protoLicense := &infov1.License{
		SpdxLicenseId: l.SPDXLicenseID(),
	}
	if l.text != "" {
		protoLicense.Source = &infov1.License_Text{
			Text: l.text,
		}
	} else if l.url != nil {
		protoLicense.Source = &infov1.License_Url{
			Url: l.url.String(),
		}
	}
	return protoLicense
}

func (*license) isLicense() {}

// Need to keep as pointer for Go nil is not nil problem.
func licenseForProtoLicense(protoLicense *infov1.License) (*license, error) {
	if protoLicense == nil {
		return nil, nil
	}
	text := protoLicense.GetText()
	var uri *url.URL
	if urlString := protoLicense.GetUrl(); urlString != "" {
		var err error
		uri, err = url.Parse(urlString)
		if err != nil {
			return nil, err
		}
	}
	return newLicense(
		protoLicense.GetSpdxLicenseId(),
		text,
		uri,
	)
}
