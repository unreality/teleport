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

package tbot

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	apiclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/retryutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	libdefaults "github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tbot/config"
	"github.com/gravitational/teleport/lib/tbot/identity"
	"github.com/gravitational/teleport/lib/tlsca"
)

const renewalRetryLimit = 5

// outputsService is responsible for generating and renewing all outputs.
//
// Eventually, this will be refactored to run a single output in a single
// service. Before that can happen, a more global cache needs to be built for
// common API calls that output generation will complete.
type outputsService struct {
	log               logrus.FieldLogger
	reloadBroadcaster *channelBroadcaster
	botIdentitySrc    botIdentitySrc
	cfg               *config.BotConfig
}

func (s *outputsService) String() string {
	return "outputs"
}

func (s *outputsService) OneShot(ctx context.Context) error {
	s.log.Info("Generating outputs.")
	err := trace.Wrap(s.renewOutputs(ctx))
	if err != nil {
		return trace.Wrap(err)
	}
	s.log.Info("Generated outputs. One-shot mode is enabled so finishing.")
	return nil
}

// renewOutputs performs a single renewal
func (s *outputsService) renewOutputs(
	ctx context.Context,
) error {
	ctx, span := tracer.Start(ctx, "outputsService/renewOutputs")
	defer span.End()

	botIdentity := s.botIdentitySrc.BotIdentity()
	client, err := clientForIdentity(ctx, s.log, s.cfg, botIdentity)
	if err != nil {
		return trace.Wrap(err)
	}
	defer client.Close()

	// create a cache shared across outputs so they don't hammer the auth
	// server with similar requests
	drc := &outputRenewalCache{
		client: client,
		cfg:    s.cfg,
	}

	// Determine the default role list based on the bot role. The role's
	// name should match the certificate's Key ID (user and role names
	// should all match bot-$name)
	botResourceName := botIdentity.X509Cert.Subject.CommonName
	defaultRoles, err := fetchDefaultRoles(ctx, client, botResourceName)
	if err != nil {
		s.log.WithError(err).Warnf("Unable to determine default roles, no roles will be requested if unspecified")
		defaultRoles = []string{}
	}

	// Next, generate impersonated certs
	for _, output := range s.cfg.Outputs {
		s.log.WithFields(logrus.Fields{
			"output": output,
		}).Info("Generating output.")

		dest := output.GetDestination()
		// Check the ACLs. We can't fix them, but we can warn if they're
		// misconfigured. We'll need to precompute a list of keys to check.
		// Note: This may only log a warning, depending on configuration.
		if err := dest.Verify(identity.ListKeys(identity.DestinationKinds()...)); err != nil {
			return trace.Wrap(err)
		}

		// Ensure this destination is also writable. This is a hard fail if
		// ACLs are misconfigured, regardless of configuration.
		// TODO: consider not making these a hard error? e.g. write other
		// destinations even if this one is broken?
		if err := identity.VerifyWrite(ctx, dest); err != nil {
			return trace.Wrap(err, "testing output destination: %s", output)
		}

		impersonatedIdentity, impersonatedClient, err := s.generateImpersonatedIdentity(
			ctx, client, botIdentity, output, defaultRoles,
		)
		if err != nil {
			return trace.Wrap(err, "generating impersonated certs for output: %s", output)
		}
		defer impersonatedClient.Close()

		s.log.WithFields(logrus.Fields{
			"identity": describeTLSIdentity(s.log, impersonatedIdentity),
			"output":   output,
		}).Debug("Fetched identity for output.")

		// Create a destination provider to bundle up all the dependencies that
		// a destination template might need to render.
		dp := &outputProvider{
			outputRenewalCache: drc,
			impersonatedClient: impersonatedClient,
		}

		if err := output.Render(ctx, dp, impersonatedIdentity); err != nil {
			s.log.WithError(err).Warnf("Failed to render output %s", output)
			return trace.Wrap(err, "rendering output: %s", output)
		}

		s.log.WithFields(logrus.Fields{
			"output": output,
		}).Info("Generated output.")
	}

	return nil
}

func (s *outputsService) Run(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "outputsService/Run")
	defer span.End()

	reloadCh, unsubscribe := s.reloadBroadcaster.subscribe()
	defer unsubscribe()

	s.log.Infof(
		"Beginning output renewal loop: ttl=%s interval=%s",
		s.cfg.CertificateTTL,
		s.cfg.RenewalInterval,
	)

	ticker := time.NewTicker(s.cfg.RenewalInterval)
	jitter := retryutils.NewJitter()
	defer ticker.Stop()
	for {
		var err error
		for attempt := 1; attempt <= renewalRetryLimit; attempt++ {
			s.log.Infof(
				"Renewing outputs. Attempt %d of %d.",
				attempt,
				renewalRetryLimit,
			)
			err = s.renewOutputs(ctx)
			if err == nil {
				break
			}

			if attempt != renewalRetryLimit {
				// exponentially back off with jitter, starting at 1 second.
				backoffTime := time.Second * time.Duration(math.Pow(2, float64(attempt-1)))
				backoffTime = jitter(backoffTime)
				s.log.WithError(err).Warnf(
					"Output renewal attempt %d of %d failed. Retrying after %s.",
					attempt,
					renewalRetryLimit,
					backoffTime,
				)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(backoffTime):
				}
			}
		}
		if err != nil {
			s.log.Warnf("%d retry attempts exhausted renewing outputs. Waiting for next normal renewal cycle in %s.", renewalRetryLimit, s.cfg.RenewalInterval)
		} else {
			s.log.Infof("Renewed outputs. Next output renewal in approximately %s.", s.cfg.RenewalInterval)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			continue
		case <-reloadCh:
			continue
		}
	}
}

// generateKeys generates TLS and SSH keypairs.
func generateKeys() (private, sshpub, tlspub []byte, err error) {
	privateKey, publicKey, err := native.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	sshPrivateKey, err := ssh.ParseRawPrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	tlsPublicKey, err := tlsca.MarshalPublicKeyFromPrivateKeyPEM(sshPrivateKey)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	return privateKey, publicKey, tlsPublicKey, nil
}

// describeTLSIdentity generates an informational message about the given
// TLS identity, appropriate for user-facing log messages.
func describeTLSIdentity(log logrus.FieldLogger, ident *identity.Identity) string {
	failedToDescribe := "failed-to-describe"
	cert := ident.X509Cert
	if cert == nil {
		log.Warn("Attempted to describe TLS identity without TLS credentials.")
		return failedToDescribe
	}

	tlsIdent, err := tlsca.FromSubject(cert.Subject, cert.NotAfter)
	if err != nil {
		log.WithError(err).Warn("Bot TLS certificate can not be parsed as an identity")
		return failedToDescribe
	}

	var principals []string
	for _, principal := range tlsIdent.Principals {
		if !strings.HasPrefix(principal, constants.NoLoginPrefix) {
			principals = append(principals, principal)
		}
	}

	duration := cert.NotAfter.Sub(cert.NotBefore)
	return fmt.Sprintf(
		"valid: after=%v, before=%v, duration=%s | kind=tls, renewable=%v, disallow-reissue=%v, roles=%v, principals=%v, generation=%v",
		cert.NotBefore.Format(time.RFC3339),
		cert.NotAfter.Format(time.RFC3339),
		duration,
		tlsIdent.Renewable,
		tlsIdent.DisallowReissue,
		tlsIdent.Groups,
		principals,
		tlsIdent.Generation,
	)
}

// identityConfigurator is a function that alters a cert request
type identityConfigurator = func(req *proto.UserCertsRequest)

// generateIdentity uses an identity to retrieve an impersonated identity.
// The `configurator` function, if not nil, can be used to add additional
// requests to the certificate request, for example to add `RouteToDatabase`
// and similar fields, however in that case it must be called with an
// impersonated identity that already has the relevant permissions, much like
// `tsh (app|db|kube) login` is already used to generate an additional set of
// certs.
func (s *outputsService) generateIdentity(
	ctx context.Context,
	client auth.ClientI,
	currentIdentity *identity.Identity,
	output config.Output,
	defaultRoles []string,
	configurator identityConfigurator,
) (*identity.Identity, error) {
	ctx, span := tracer.Start(ctx, "outputsService/generateIdentity")
	defer span.End()

	// TODO: enforce expiration > renewal period (by what margin?)
	//   This should be ignored if a renewal has been triggered manually or
	//   by a CA rotation.

	// Generate a fresh keypair for the impersonated identity. We don't care to
	// reuse keys here: impersonated certs might not be as well-protected so
	// constantly rotating private keys
	privateKey, publicKey, err := native.GenerateKeyPair()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var roleRequests []string
	if roles := output.GetRoles(); len(roles) > 0 {
		roleRequests = roles
	} else {
		s.log.Debugf("Output specified no roles, defaults will be requested: %v", defaultRoles)
		roleRequests = defaultRoles
	}

	req := proto.UserCertsRequest{
		PublicKey:      publicKey,
		Username:       currentIdentity.X509Cert.Subject.CommonName,
		Expires:        time.Now().Add(s.cfg.CertificateTTL),
		RoleRequests:   roleRequests,
		RouteToCluster: currentIdentity.ClusterName,

		// Make sure to specify this is an impersonated cert request. If unset,
		// auth cannot differentiate renewable vs impersonated requests when
		// len(roleRequests) == 0.
		UseRoleRequests: true,
	}

	if configurator != nil {
		configurator(&req)
	}

	// First, ask the auth server to generate a new set of certs with a new
	// expiration date.
	certs, err := client.GenerateUserCerts(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// The root CA included with the returned user certs will only contain the
	// Teleport User CA. We'll also need the host CA for future API calls.
	localCA, err := client.GetClusterCACert(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	caCerts, err := tlsca.ParseCertificatePEMs(localCA.TLSCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Append the host CAs from the auth server.
	for _, cert := range caCerts {
		pemBytes, err := tlsca.MarshalCertificatePEM(cert)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		certs.TLSCACerts = append(certs.TLSCACerts, pemBytes)
	}

	// Do not trust SSH CA certs as returned by GenerateUserCerts() with an
	// impersonated identity. It only returns the SSH UserCA in this context,
	// but we also need the HostCA and can't directly set `includeHostCA` as
	// part of the UserCertsRequest.
	// Instead, copy the SSHCACerts from the primary identity.
	certs.SSHCACerts = currentIdentity.SSHCACertBytes

	newIdentity, err := identity.ReadIdentityFromStore(&identity.LoadIdentityParams{
		PrivateKeyBytes: privateKey,
		PublicKeyBytes:  publicKey,
	}, certs)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return newIdentity, nil
}

func getDatabase(ctx context.Context, clt auth.ClientI, name string) (types.Database, error) {
	ctx, span := tracer.Start(ctx, "getDatabase")
	defer span.End()

	servers, err := apiclient.GetAllResources[types.DatabaseServer](ctx, clt, &proto.ListResourcesRequest{
		Namespace:           defaults.Namespace,
		ResourceType:        types.KindDatabaseServer,
		PredicateExpression: makeNameOrDiscoveredNamePredicate(name),
		Limit:               int32(defaults.DefaultChunkSize),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var databases []types.Database
	for _, server := range servers {
		databases = append(databases, server.GetDatabase())
	}

	databases = types.DeduplicateDatabases(databases)
	db, err := chooseOneDatabase(databases, name)
	return db, trace.Wrap(err)
}

func (s *outputsService) getRouteToDatabase(ctx context.Context, client auth.ClientI, output *config.DatabaseOutput) (proto.RouteToDatabase, error) {
	ctx, span := tracer.Start(ctx, "outputsService/getRouteToDatabase")
	defer span.End()

	if output.Service == "" {
		return proto.RouteToDatabase{}, nil
	}

	db, err := getDatabase(ctx, client, output.Service)
	if err != nil {
		return proto.RouteToDatabase{}, trace.Wrap(err)
	}
	// make sure the output matches the fully resolved db name, since it may
	// have been just a "discovered name".
	output.Service = db.GetName()

	username := output.Username
	if db.GetProtocol() == libdefaults.ProtocolMongoDB && username == "" {
		// This isn't strictly a runtime error so killing the process seems
		// wrong. We'll just loudly warn about it.
		s.log.Errorf("Database `username` field for %q is unset but is required for MongoDB databases.", output.Service)
	} else if db.GetProtocol() == libdefaults.ProtocolRedis && username == "" {
		// Per tsh's lead, fall back to the default username.
		username = libdefaults.DefaultRedisUsername
	}

	return proto.RouteToDatabase{
		ServiceName: output.Service,
		Protocol:    db.GetProtocol(),
		Database:    output.Database,
		Username:    username,
	}, nil
}

func getKubeCluster(ctx context.Context, clt auth.ClientI, name string) (types.KubeCluster, error) {
	ctx, span := tracer.Start(ctx, "getKubeCluster")
	defer span.End()

	servers, err := apiclient.GetAllResources[types.KubeServer](ctx, clt, &proto.ListResourcesRequest{
		Namespace:           defaults.Namespace,
		ResourceType:        types.KindKubeServer,
		PredicateExpression: makeNameOrDiscoveredNamePredicate(name),
		Limit:               int32(defaults.DefaultChunkSize),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var clusters []types.KubeCluster
	for _, server := range servers {
		clusters = append(clusters, server.GetCluster())
	}

	clusters = types.DeduplicateKubeClusters(clusters)
	cluster, err := chooseOneKubeCluster(clusters, name)
	return cluster, trace.Wrap(err)
}

func getApp(ctx context.Context, clt auth.ClientI, appName string) (types.Application, error) {
	ctx, span := tracer.Start(ctx, "getApp")
	defer span.End()

	servers, err := apiclient.GetAllResources[types.AppServer](ctx, clt, &proto.ListResourcesRequest{
		Namespace:           defaults.Namespace,
		ResourceType:        types.KindAppServer,
		PredicateExpression: fmt.Sprintf(`name == "%s"`, appName),
		Limit:               1,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var apps []types.Application
	for _, server := range servers {
		apps = append(apps, server.GetApp())
	}
	apps = types.DeduplicateApps(apps)

	if len(apps) == 0 {
		return nil, trace.BadParameter("app %q not found", appName)
	}

	return apps[0], nil
}

func (s *outputsService) getRouteToApp(ctx context.Context, botIdentity *identity.Identity, client auth.ClientI, output *config.ApplicationOutput) (proto.RouteToApp, error) {
	ctx, span := tracer.Start(ctx, "outputsService/getRouteToApp")
	defer span.End()

	app, err := getApp(ctx, client, output.AppName)
	if err != nil {
		return proto.RouteToApp{}, trace.Wrap(err)
	}

	// TODO: AWS?
	ws, err := client.CreateAppSession(ctx, types.CreateAppSessionRequest{
		ClusterName: botIdentity.ClusterName,
		Username:    botIdentity.X509Cert.Subject.CommonName,
		PublicAddr:  app.GetPublicAddr(),
	})
	if err != nil {
		return proto.RouteToApp{}, trace.Wrap(err)
	}

	err = auth.WaitForAppSession(ctx, ws.GetName(), ws.GetUser(), client)
	if err != nil {
		return proto.RouteToApp{}, trace.Wrap(err)
	}

	return proto.RouteToApp{
		Name:        app.GetName(),
		SessionID:   ws.GetName(),
		PublicAddr:  app.GetPublicAddr(),
		ClusterName: botIdentity.ClusterName,
	}, nil
}

// generateImpersonatedIdentity generates an impersonated identity for a given
// output. It also returns a client that is authenticated with that
// impersonated identity.
func (s *outputsService) generateImpersonatedIdentity(
	ctx context.Context,
	botClient auth.ClientI,
	botIdentity *identity.Identity,
	output config.Output,
	defaultRoles []string,
) (impersonatedIdentity *identity.Identity, impersonatedClient auth.ClientI, err error) {
	ctx, span := tracer.Start(ctx, "outputsService/generateImpersonatedIdentity")
	defer span.End()

	impersonatedIdentity, err = s.generateIdentity(
		ctx, botClient, botIdentity, output, defaultRoles, nil,
	)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	// create a client that uses the impersonated identity, so that when we
	// fetch information, we can ensure access rights are enforced.
	impersonatedClient, err = clientForIdentity(ctx, s.log, s.cfg, impersonatedIdentity)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	defer func() {
		// In success cases, this client is used by the caller and they manage
		// closing, in failure cases, we need to close the client.
		if err != nil && impersonatedClient != nil {
			impersonatedClient.Close()
		}
	}()

	// Now that we have an initial impersonated identity, we can use it to
	// request any app/db/etc certs
	switch output := output.(type) {
	case *config.IdentityOutput:
		if output.Cluster == "" {
			return impersonatedIdentity, impersonatedClient, nil
		}

		routedIdentity, err := s.generateIdentity(ctx, botClient, impersonatedIdentity, output, defaultRoles, func(req *proto.UserCertsRequest) {
			req.RouteToCluster = output.Cluster
		},
		)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		return routedIdentity, impersonatedClient, nil
	case *config.DatabaseOutput:
		route, err := s.getRouteToDatabase(ctx, impersonatedClient, output)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		// The impersonated identity is not allowed to reissue certificates,
		// so we'll request the database access identity using the main bot
		// identity (having gathered the necessary info for RouteToDatabase
		// using the correct impersonated unroutedIdentity.)
		routedIdentity, err := s.generateIdentity(ctx, botClient, impersonatedIdentity, output, defaultRoles, func(req *proto.UserCertsRequest) {
			req.RouteToDatabase = route
		})
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		s.log.Infof("Generated identity for database %q", output.Service)

		return routedIdentity, impersonatedClient, nil
	case *config.KubernetesOutput:
		kc, err := getKubeCluster(ctx, impersonatedClient, output.KubernetesCluster)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		// make sure the output matches the fully resolved kube cluster name,
		// since it may have been just a "discovered name".
		output.KubernetesCluster = kc.GetName()
		// Note: the Teleport server does attempt to verify k8s cluster names
		// and will fail to generate certs if the cluster doesn't exist or is
		// offline.
		routedIdentity, err := s.generateIdentity(ctx, botClient, impersonatedIdentity, output, defaultRoles, func(req *proto.UserCertsRequest) {
			req.KubernetesCluster = output.KubernetesCluster
		})
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		s.log.Infof("Generated identity for Kubernetes cluster %q", output.KubernetesCluster)

		return routedIdentity, impersonatedClient, nil
	case *config.ApplicationOutput:
		routeToApp, err := s.getRouteToApp(ctx, botIdentity, impersonatedClient, output)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		routedIdentity, err := s.generateIdentity(ctx, botClient, impersonatedIdentity, output, defaultRoles, func(req *proto.UserCertsRequest) {
			req.RouteToApp = routeToApp
		})
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		s.log.Infof("Generated identity for app %q", output.AppName)

		return routedIdentity, impersonatedClient, nil
	case *config.SSHHostOutput:
		return impersonatedIdentity, impersonatedClient, nil
	case *config.UnstableClientCredentialOutput:
		return impersonatedIdentity, impersonatedClient, nil
	default:
		return nil, nil, trace.BadParameter("generateImpersonatedIdentity does not support output type (%T)", output)
	}
}

// fetchDefaultRoles requests the bot's own role from the auth server and
// extracts its full list of allowed roles.
func fetchDefaultRoles(ctx context.Context, roleGetter services.RoleGetter, botRole string) ([]string, error) {
	role, err := roleGetter.GetRole(ctx, botRole)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	conditions := role.GetImpersonateConditions(types.Allow)
	return conditions.Roles, nil
}

// outputRenewalCache is used to cache information during a renewal to pass
// to outputs. This prevents them all hammering the auth server with
// requests for the same information. This is shared between all of the
// outputs.
type outputRenewalCache struct {
	client auth.ClientI

	cfg *config.BotConfig
	mu  sync.Mutex
	// These are protected by getter/setters with mutex locks
	_cas       map[types.CertAuthType][]types.CertAuthority
	_authPong  *proto.PingResponse
	_proxyPong *webclient.PingResponse
}

func (orc *outputRenewalCache) getCertAuthorities(
	ctx context.Context, caType types.CertAuthType,
) ([]types.CertAuthority, error) {
	if cas := orc._cas[caType]; len(cas) > 0 {
		return cas, nil
	}

	cas, err := orc.client.GetCertAuthorities(ctx, caType, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if orc._cas == nil {
		orc._cas = map[types.CertAuthType][]types.CertAuthority{}
	}
	orc._cas[caType] = cas
	return cas, nil
}

// GetCertAuthorities returns the possibly cached CAs of the given type and
// requests them from the server if unavailable.
func (orc *outputRenewalCache) GetCertAuthorities(
	ctx context.Context, caType types.CertAuthType,
) ([]types.CertAuthority, error) {
	orc.mu.Lock()
	defer orc.mu.Unlock()
	return orc.getCertAuthorities(ctx, caType)
}

func (orc *outputRenewalCache) authPing(ctx context.Context) (*proto.PingResponse, error) {
	if orc._authPong != nil {
		return orc._authPong, nil
	}

	pong, err := orc.client.Ping(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	orc._authPong = &pong

	return &pong, nil
}

// AuthPing pings the auth server and returns the (possibly cached) response.
func (orc *outputRenewalCache) AuthPing(ctx context.Context) (*proto.PingResponse, error) {
	orc.mu.Lock()
	defer orc.mu.Unlock()
	return orc.authPing(ctx)
}

func (orc *outputRenewalCache) proxyPing(ctx context.Context) (*webclient.PingResponse, error) {
	if orc._proxyPong != nil {
		return orc._proxyPong, nil
	}

	// Note: this relies on the auth server's proxy address. We could
	// potentially support some manual parameter here in the future if desired.
	authPong, err := orc.authPing(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// We use find instead of Ping as it's less resource intense and we can
	// ping the AuthServer directly for its configuration if necessary.
	proxyPong, err := webclient.Find(&webclient.Config{
		Context:   ctx,
		ProxyAddr: authPong.ProxyPublicAddr,
		Insecure:  orc.cfg.Insecure,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	orc._proxyPong = proxyPong

	return proxyPong, nil
}

// ProxyPing returns a (possibly cached) ping response from the Teleport proxy.
// Note that it relies on the auth server being configured with a sane proxy
// public address.
func (orc *outputRenewalCache) ProxyPing(ctx context.Context) (*webclient.PingResponse, error) {
	orc.mu.Lock()
	defer orc.mu.Unlock()
	return orc.proxyPing(ctx)
}

// Config returns the bots config.
func (orc *outputRenewalCache) Config() *config.BotConfig {
	return orc.cfg
}

// outputProvider bundles the dependencies an output needs in order to render.
// It provides a handy point for controlling what templates are allowed to call
// and how they are allowed to call them. This makes ensuring that they call
// RPCs with the correct identity much easier.
type outputProvider struct {
	// we embed the cache shared across all outputs to provide access to
	// non-identity specific methods like `AuthPing`.
	*outputRenewalCache
	// impersonatedClient is a client using the impersonated identity configured
	// for that output.
	impersonatedClient auth.ClientI
}

// GetRemoteClusters uses the impersonatedClient to call GetRemoteClusters.
func (op *outputProvider) GetRemoteClusters(opts ...services.MarshalOption) ([]types.RemoteCluster, error) {
	return op.impersonatedClient.GetRemoteClusters(opts...)
}

// GenerateHostCert uses the impersonatedClient to call GenerateHostCert.
func (op *outputProvider) GenerateHostCert(ctx context.Context, key []byte, hostID, nodeName string, principals []string, clusterName string, role types.SystemRole, ttl time.Duration) ([]byte, error) {
	return op.impersonatedClient.GenerateHostCert(ctx, key, hostID, nodeName, principals, clusterName, role, ttl)
}

// GetCertAuthority uses the impersonatedClient to call GetCertAuthority.
func (op *outputProvider) GetCertAuthority(ctx context.Context, id types.CertAuthID, loadKeys bool) (types.CertAuthority, error) {
	return op.impersonatedClient.GetCertAuthority(ctx, id, loadKeys)
}

// chooseOneDatabase chooses one matched database by name, or tries to choose
// one database by unambiguous "discovered name".
func chooseOneDatabase(databases []types.Database, name string) (types.Database, error) {
	return chooseOneResource(databases, name, "database")
}

// chooseOneKubeCluster chooses one matched kube cluster by name, or tries to
// choose one kube cluster by unambiguous "discovered name".
func chooseOneKubeCluster(clusters []types.KubeCluster, name string) (types.KubeCluster, error) {
	return chooseOneResource(clusters, name, "kubernetes cluster")
}

// chooseOneResource chooses one matched resource by name, or tries to choose
// one resource by unambiguous "discovered name".
func chooseOneResource[T types.ResourceWithLabels](resources []T, name, resDesc string) (T, error) {
	for _, r := range resources {
		if r.GetName() == name {
			return r, nil
		}
	}

	// look for an unambiguous "discovered name" match as a fallback.
	var matches []T
	for _, r := range resources {
		discoveredName, ok := r.GetLabel(types.DiscoveredNameLabel)
		if ok && discoveredName == name {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 0:
		var out T
		return out, trace.NotFound("%s %q not found", resDesc, name)
	case 1:
		return matches[0], nil
	default:
		var out T
		errMsg := formatAmbiguousMessage(name, resDesc, matches)
		return out, trace.BadParameter(errMsg)
	}
}

// formatAmbiguousMessage formats a generic error message that describes an ambiguous
// auto-discovered resource name match error.
func formatAmbiguousMessage[T types.ResourceWithLabels](name, resDesc string, matches []T) string {
	matchedNames := make([]string, 0, len(matches))
	for _, match := range matches {
		matchedNames = append(matchedNames, match.GetName())
	}
	slices.Sort(matchedNames)
	return fmt.Sprintf(`%q matches multiple auto-discovered %ss:
%v

Use the full resource name that was generated by the Teleport Discovery service`,
		name, resDesc, strings.Join(matchedNames, "\n"))
}

// makeNameOrDiscoveredNamePredicate returns a predicate that matches resources
// by name or by "discovered name" label.
func makeNameOrDiscoveredNamePredicate(name string) string {
	matchName := fmt.Sprintf("name == %q", name)
	matchDiscoveredName := fmt.Sprintf("labels[%q] == %q",
		types.DiscoveredNameLabel, name,
	)
	return fmt.Sprintf("(%v) || (%v)",
		matchName, matchDiscoveredName,
	)
}
