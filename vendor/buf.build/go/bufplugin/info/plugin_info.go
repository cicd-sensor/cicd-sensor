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

	infov1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/info/v1"
)

// PluginInfo contains information about a plugin.
type PluginInfo interface {
	// Documentation returns the documentation of the plugin.
	//
	// Optional.
	Documentation() string
	// License returns the license of the plugin.
	//
	// Optional.
	License() License

	toProto() *infov1.PluginInfo

	isPluginInfo()
}

// NewPluginInfoForSpec returns a new PluginInfo for the given Spec.
func NewPluginInfoForSpec(spec *Spec) (PluginInfo, error) {
	if err := ValidateSpec(spec); err != nil {
		return nil, err
	}

	var license *license
	if spec.SPDXLicenseID != "" || spec.LicenseText != "" || spec.LicenseURL != "" {
		var licenseURI *url.URL
		var err error
		if spec.LicenseURL != "" {
			licenseURI, err = url.Parse(spec.LicenseURL)
			if err != nil {
				return nil, err
			}
		}
		license, err = newLicense(
			spec.SPDXLicenseID,
			spec.LicenseText,
			licenseURI,
		)
		if err != nil {
			return nil, err
		}
	}
	return newPluginInfo(spec.Documentation, license)
}

// *** PRIVATE ***

type pluginInfo struct {
	documentation string
	// Need to keep as pointer for Go nil is not nil problem.
	license *license
}

func newPluginInfo(
	documentation string,
	license *license,
) (*pluginInfo, error) {
	return &pluginInfo{
		documentation: documentation,
		license:       license,
	}, nil
}

func (p *pluginInfo) Documentation() string {
	return p.documentation
}

func (p *pluginInfo) License() License {
	// Go nil is not nil problem.
	if p.license == nil {
		return nil
	}
	return p.license
}

func (p *pluginInfo) toProto() *infov1.PluginInfo {
	return &infov1.PluginInfo{
		Documentation: p.documentation,
		License:       p.license.toProto(),
	}
}

func (*pluginInfo) isPluginInfo() {}

func pluginInfoForProtoPluginInfo(protoPluginInfo *infov1.PluginInfo) (PluginInfo, error) {
	if protoPluginInfo == nil {
		return nil, nil
	}
	license, err := licenseForProtoLicense(protoPluginInfo.GetLicense())
	if err != nil {
		return nil, err
	}
	return newPluginInfo(protoPluginInfo.GetDocumentation(), license)
}
