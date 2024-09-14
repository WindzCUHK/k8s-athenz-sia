// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config defines all the configuration parameters. It reads configuration from environment variables and command-line arguments.
package config

// loadDerivedConfig loads functions from files with prefix "derived-" under /pkg/config
func (idCfg *IdentityConfig) loadDerivedConfig() error {
	// TODO:
	// if err := idCfg.derivedServiceCert(); err != nil {
	// 	return err
	// }

	// TODO:
	// if err := idCfg.derivedTargetDomainRoles(); err != nil {
	// 	return err
	// }

	if err := idCfg.derivedRoleCertConfig(); err != nil {
		return err
	}

	// TODO:
	// if err := idCfg.derivedAccessTokenConfig(); err != nil {
	// 	return err
	// }

	// TODO:
	// if err := idCfg.derivedRoleTokenConfig(); err != nil {
	// 	return err
	// }

	return nil
}