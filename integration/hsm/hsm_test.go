/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package hsm

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/keystore"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/etcdbk"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/utils"
)

func TestMain(m *testing.M) {
	// Enable HSM feature.
	// This is safe to do here, as all tests in this package require HSM to be
	// enabled.
	modules.SetModules(&modules.TestModules{
		TestBuildType: modules.BuildEnterprise,
		TestFeatures: modules.Features{
			HSM: true,
		},
	})

	os.Exit(m.Run())
}

func newHSMAuthConfig(t *testing.T, storageConfig *backend.Config, log utils.Logger) *servicecfg.Config {
	config := newAuthConfig(t, log)

	config.Auth.StorageConfig = *storageConfig

	if gcpKeyring := os.Getenv("TEST_GCP_KMS_KEYRING"); gcpKeyring != "" {
		config.Auth.KeyStore.GCPKMS.KeyRing = gcpKeyring
		config.Auth.KeyStore.GCPKMS.ProtectionLevel = "HSM"
	} else {
		config.Auth.KeyStore = keystore.SetupSoftHSMTest(t)
	}

	return config
}

func etcdBackendConfig(t *testing.T) *backend.Config {
	prefix := uuid.NewString()
	cfg := &backend.Config{
		Type: "etcd",
		Params: backend.Params{
			"peers":         []string{etcdTestEndpoint()},
			"prefix":        prefix,
			"tls_key_file":  "../../examples/etcd/certs/client-key.pem",
			"tls_cert_file": "../../examples/etcd/certs/client-cert.pem",
			"tls_ca_file":   "../../examples/etcd/certs/ca-cert.pem",
		},
	}
	t.Cleanup(func() {
		bk, err := etcdbk.New(context.Background(), cfg.Params)
		require.NoError(t, err)

		// Based on [backend.Sanitizer] these define the possible range that
		// needs to be cleaned up at the end of the test.
		firstPossibleKey := []byte("+")
		lastPossibleKey := backend.RangeEnd([]byte("z"))
		require.NoError(t, bk.DeleteRange(context.Background(), firstPossibleKey, lastPossibleKey),
			"failed to clean up etcd backend")
	})
	return cfg
}

// etcdTestEndpoint returns etcd host used in tests.
func etcdTestEndpoint() string {
	host := os.Getenv("TELEPORT_ETCD_TEST_ENDPOINT")
	if host != "" {
		return host
	}
	return "https://127.0.0.1:2379"
}

func liteBackendConfig(t *testing.T) *backend.Config {
	return &backend.Config{
		Type: lite.GetName(),
		Params: backend.Params{
			"path": t.TempDir(),
		},
	}
}

func requireHSMAvailable(t *testing.T) {
	if os.Getenv("SOFTHSM2_PATH") == "" && os.Getenv("TEST_GCP_KMS_KEYRING") == "" {
		t.Skip("Skipping test because neither SOFTHSM2_PATH or TEST_GCP_KMS_KEYRING are set")
	}
}

func requireETCDAvailable(t *testing.T) {
	if os.Getenv("TELEPORT_ETCD_TEST") == "" {
		t.Skip("Skipping test because TELEPORT_ETCD_TEST is not set")
	}
}

// Tests a single CA rotation with a single HSM auth server
func TestHSMRotation(t *testing.T) {
	requireHSMAvailable(t)

	// pick a conservative timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	t.Cleanup(cancel)
	log := utils.NewLoggerForTests()

	log.Debug("TestHSMRotation: starting auth server")
	authConfig := newHSMAuthConfig(t, liteBackendConfig(t), log)
	auth1 := newTeleportService(t, authConfig, "auth1")
	allServices := teleportServices{auth1}

	log.Debug("TestHSMRotation: waiting for auth server to start")
	err := auth1.start(ctx)
	require.NoError(t, err, trace.DebugReport(err))
	t.Cleanup(func() {
		require.NoError(t, auth1.process.GetAuthServer().GetKeyStore().DeleteUnusedKeys(ctx, nil))
	})

	// start a proxy to make sure it can get creds at each stage of rotation
	log.Debug("TestHSMRotation: starting proxy")
	proxy := newTeleportService(t, newProxyConfig(t, auth1.authAddr(t), log), "proxy")
	require.NoError(t, proxy.start(ctx))
	allServices = append(allServices, proxy)

	log.Debug("TestHSMRotation: sending rotation request init")
	err = auth1.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
		Type:        types.HostCA,
		TargetPhase: types.RotationPhaseInit,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
	require.NoError(t, allServices.waitForPhaseChange(ctx))

	log.Debug("TestHSMRotation: sending rotation request update_clients")
	err = auth1.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
		Type:        types.HostCA,
		TargetPhase: types.RotationPhaseUpdateClients,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
	require.NoError(t, allServices.waitForRestart(ctx))

	log.Debug("TestHSMRotation: sending rotation request update_servers")
	err = auth1.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
		Type:        types.HostCA,
		TargetPhase: types.RotationPhaseUpdateServers,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
	require.NoError(t, allServices.waitForRestart(ctx))

	log.Debug("TestHSMRotation: sending rotation request standby")
	err = auth1.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
		Type:        types.HostCA,
		TargetPhase: types.RotationPhaseStandby,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
	require.NoError(t, allServices.waitForRestart(ctx))
}

func getAdminClient(authDataDir string, authAddr string) (*auth.Client, error) {
	identity, err := auth.ReadLocalIdentity(
		filepath.Join(authDataDir, teleport.ComponentProcess),
		auth.IdentityID{Role: types.RoleAdmin})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tlsConfig, err := identity.TLSConfig(nil /*cipherSuites*/)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clt, err := auth.NewClient(client.Config{
		Addrs: []string{authAddr},
		Credentials: []client.Credentials{
			client.LoadTLS(tlsConfig),
		},
		CircuitBreakerConfig: breaker.NoopBreakerConfig(),
	})
	return clt, trace.Wrap(err)
}

func testAdminClient(t *testing.T, authDataDir string, authAddr string) {
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		clt, err := getAdminClient(authDataDir, authAddr)
		assert.NoError(t, err)
		if err != nil {
			return
		}
		// Make sure it succeeds twice in a row, we might be hitting a load
		// balancer in front of two auths, this gives a better chance of testing
		// both
		for i := 0; i < 2; i++ {
			_, err := clt.GetClusterName()
			assert.NoError(t, err)
		}
	}, 10*time.Second, time.Second, "admin client failed test call to GetClusterName")
}

// Tests multiple CA rotations and rollbacks with 2 HSM auth servers in an HA configuration
func TestHSMDualAuthRotation(t *testing.T) {
	// TODO(nklaassen): fix this test and re-enable it.
	// https://github.com/gravitational/teleport/issues/20217
	t.Skip("TestHSMDualAuthRotation is temporarily disabled due to flakiness")

	requireHSMAvailable(t)
	requireETCDAvailable(t)

	// pick a global timeout for the test
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	log := utils.NewLoggerForTests()
	storageConfig := etcdBackendConfig(t)

	// start a cluster with 1 auth server and a proxy
	log.Debug("TestHSMDualAuthRotation: Starting auth server 1")
	auth1Config := newHSMAuthConfig(t, storageConfig, log)
	auth1 := newTeleportService(t, auth1Config, "auth1")
	t.Cleanup(func() {
		require.NoError(t, auth1.process.GetAuthServer().GetKeyStore().DeleteUnusedKeys(ctx, nil),
			"failed to delete hsm keys during test cleanup")
	})
	authServices := teleportServices{auth1}
	allServices := append(teleportServices{}, authServices...)
	require.NoError(t, authServices.start(ctx), "auth service failed initial startup")

	log.Debug("TestHSMDualAuthRotation: Starting load balancer")
	lb, err := utils.NewLoadBalancer(
		ctx,
		*utils.MustParseAddr(net.JoinHostPort("localhost", "0")),
		auth1.authAddr(t),
	)
	require.NoError(t, err)
	require.NoError(t, lb.Listen())
	go lb.Serve()
	t.Cleanup(func() { require.NoError(t, lb.Close()) })

	// start a proxy to make sure it can get creds at each stage of rotation
	log.Debug("TestHSMDualAuthRotation: Starting proxy")
	proxyConfig := newProxyConfig(t, utils.FromAddr(lb.Addr()), log)
	proxy := newTeleportService(t, proxyConfig, "proxy")
	require.NoError(t, proxy.start(ctx), "proxy failed initial startup")
	allServices = append(allServices, proxy)

	// add a new auth server
	log.Debug("TestHSMDualAuthRotation: Starting auth server 2")
	auth2Config := newHSMAuthConfig(t, storageConfig, log)
	auth2 := newTeleportService(t, auth2Config, "auth2")
	require.NoError(t, auth2.start(ctx))
	t.Cleanup(func() {
		require.NoError(t, auth2.process.GetAuthServer().GetKeyStore().DeleteUnusedKeys(ctx, nil))
	})
	authServices = append(authServices, auth2)
	allServices = append(allServices, auth2)

	testAuth2Client := func(t *testing.T) {
		testAdminClient(t, auth2Config.DataDir, auth2.authAddrString(t))
	}
	testAuth2Client(t)

	stages := []struct {
		targetPhase string
		verify      func(t *testing.T)
	}{
		{
			targetPhase: types.RotationPhaseInit,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForPhaseChange(ctx))
				require.NoError(t, authServices.waitForLocalAdditionalKeys(ctx))
				testAuth2Client(t)
			},
		},
		{
			targetPhase: types.RotationPhaseUpdateClients,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testAuth2Client(t)
			},
		},
		{
			targetPhase: types.RotationPhaseUpdateServers,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testAuth2Client(t)
			},
		},
		{
			targetPhase: types.RotationPhaseStandby,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testAuth2Client(t)
			},
		},
	}

	// do a full rotation
	for _, stage := range stages {
		log.Debugf("TestHSMDualAuthRotation: Sending rotate request %s", stage.targetPhase)
		require.NoError(t, auth1.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
			Type:        types.HostCA,
			TargetPhase: stage.targetPhase,
			Mode:        types.RotationModeManual,
		}))
		stage.verify(t)
	}

	// Safe to send traffic to new auth server now that a full rotation has been completed.
	lb.AddBackend(auth2.authAddr(t))

	testLoadBalancedClient := func(t *testing.T) {
		testAdminClient(t, auth2Config.DataDir, lb.Addr().String())
	}
	testLoadBalancedClient(t)

	// Do another full rotation from the new auth server
	for _, stage := range stages {
		log.Debugf("TestHSMDualAuthRotation: Sending rotate request %s", stage.targetPhase)
		require.NoError(t, auth2.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
			Type:        types.HostCA,
			TargetPhase: stage.targetPhase,
			Mode:        types.RotationModeManual,
		}))
		stage.verify(t)
	}

	// test rollbacks
	stages = []struct {
		targetPhase string
		verify      func(t *testing.T)
	}{
		{
			targetPhase: types.RotationPhaseInit,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForPhaseChange(ctx))
				require.NoError(t, authServices.waitForLocalAdditionalKeys(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseRollback,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseStandby,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseInit,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForPhaseChange(ctx))
				require.NoError(t, authServices.waitForLocalAdditionalKeys(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseUpdateClients,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseRollback,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseStandby,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseInit,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForPhaseChange(ctx))
				require.NoError(t, authServices.waitForLocalAdditionalKeys(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseUpdateClients,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseUpdateServers,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseRollback,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseStandby,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testLoadBalancedClient(t)
			},
		},
	}
	for _, stage := range stages {
		log.Debugf("TestHSMDualAuthRotation: Sending rotate request %s", stage.targetPhase)
		require.NoError(t, auth1.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
			Type:        types.HostCA,
			TargetPhase: stage.targetPhase,
			Mode:        types.RotationModeManual,
		}))
		stage.verify(t)
	}
}

// Tests a dual-auth server migration from raw keys to HSM keys
func TestHSMMigrate(t *testing.T) {
	requireHSMAvailable(t)
	requireETCDAvailable(t)

	// pick a global timeout for the test
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	log := utils.NewLoggerForTests()
	storageConfig := etcdBackendConfig(t)

	// start a dual auth non-hsm cluster
	log.Debug("TestHSMMigrate: Starting auth server 1")
	auth1Config := newHSMAuthConfig(t, storageConfig, log)
	auth1Config.Auth.KeyStore = keystore.Config{}
	auth1 := newTeleportService(t, auth1Config, "auth1")
	auth2Config := newHSMAuthConfig(t, storageConfig, log)
	auth2Config.Auth.KeyStore = keystore.Config{}
	auth2 := newTeleportService(t, auth2Config, "auth2")
	require.NoError(t, auth1.start(ctx))
	require.NoError(t, auth2.start(ctx))

	// Replace configured addresses with port set to 0 with the actual port
	// number so they are stable across hard restarts.
	auth1Config.Auth.ListenAddr = auth1.authAddr(t)
	auth2Config.Auth.ListenAddr = auth2.authAddr(t)

	log.Debug("TestHSMMigrate: Starting load balancer")
	lb, err := utils.NewLoadBalancer(
		ctx,
		*utils.MustParseAddr(net.JoinHostPort("localhost", "0")),
		auth1.authAddr(t),
		auth2.authAddr(t),
	)
	require.NoError(t, err)
	require.NoError(t, lb.Listen())
	go lb.Serve()
	t.Cleanup(func() { require.NoError(t, lb.Close()) })

	// start a proxy to make sure it can get creds at each stage of migration
	log.Debug("TestHSMMigrate: Starting proxy")
	proxyConfig := newProxyConfig(t, utils.FromAddr(lb.Addr()), log)
	proxy := newTeleportService(t, proxyConfig, "proxy")
	require.NoError(t, proxy.start(ctx))

	testClient := func(t *testing.T) {
		testAdminClient(t, auth1Config.DataDir, lb.Addr().String())
	}
	testClient(t)

	// Phase 1: migrate auth1 to HSM
	auth1.process.Close()
	require.NoError(t, auth1.waitForShutdown(ctx))
	auth1Config.Auth.KeyStore = keystore.SetupSoftHSMTest(t)
	auth1 = newTeleportService(t, auth1Config, "auth1")
	require.NoError(t, auth1.start(ctx))

	testClient(t)

	authServices := teleportServices{auth1, auth2}
	allServices := teleportServices{auth1, auth2, proxy}

	stages := []struct {
		targetPhase string
		verify      func(t *testing.T)
	}{
		{
			targetPhase: types.RotationPhaseInit,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForPhaseChange(ctx))
				require.NoError(t, authServices.waitForLocalAdditionalKeys(ctx))
				testClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseUpdateClients,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseUpdateServers,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testClient(t)
			},
		},
		{
			targetPhase: types.RotationPhaseStandby,
			verify: func(t *testing.T) {
				require.NoError(t, allServices.waitForRestart(ctx))
				testClient(t)
			},
		},
	}

	// Do a full rotation to get HSM keys for auth1 into the CA.
	for _, stage := range stages {
		log.Debugf("TestHSMMigrate: Sending rotate request %s", stage.targetPhase)
		require.NoError(t, auth1.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
			Type:        types.HostCA,
			TargetPhase: stage.targetPhase,
			Mode:        types.RotationModeManual,
		}))
		stage.verify(t)
	}

	// Phase 2: migrate auth2 to HSM
	auth2.process.Close()
	require.NoError(t, auth2.waitForShutdown(ctx))
	auth2Config.Auth.KeyStore = keystore.SetupSoftHSMTest(t)
	auth2 = newTeleportService(t, auth2Config, "auth2")
	require.NoError(t, auth2.start(ctx))

	authServices = teleportServices{auth1, auth2}
	allServices = teleportServices{auth1, auth2, proxy}

	testClient(t)

	// Do another full rotation to get HSM keys for auth2 into the CA.
	for _, stage := range stages {
		log.Debugf("TestHSMMigrate: Sending rotate request %s", stage.targetPhase)
		require.NoError(t, auth2.process.GetAuthServer().RotateCertAuthority(ctx, types.RotateRequest{
			Type:        types.HostCA,
			TargetPhase: stage.targetPhase,
			Mode:        types.RotationModeManual,
		}))
		stage.verify(t)
	}

	testClient(t)
}
