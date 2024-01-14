package auth

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

var ErrOIDCNoRoles = trace.BadParameter("user does not belong to any groups configured in oidc role map")
var ExternalSkippedClaims = []string{"azp", "nonce", "state", "at_hash", "iss", "jti", "session_state", "typ", "aud", "acr"}

type OIDCAuthService struct {
	s *Server
}

func NewOIDCAuthService(s *Server) *OIDCAuthService {
	as := OIDCAuthService{s: s}

	return &as
}

func (a *OIDCAuthService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := a.s.GetOIDCConnector(ctx, req.ConnectorID, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	redirectURL, err := services.GetRedirectURL(connector, a.s.getProxyPublicAddr())

	if err != nil {
		return nil, trace.Wrap(err)
	}

	p, err := oidc.NewProvider(ctx, connector.GetIssuerURL())

	if err != nil {
		return nil, trace.Wrap(err)
	}

	oauthConfig := oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	req.StateToken, err = utils.CryptoRandomHex(TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	nonce, err := utils.CryptoRandomHex(TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req.RedirectURL = oauthConfig.AuthCodeURL(req.StateToken, oidc.Nonce(nonce))

	log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf(
		"Redirect URL: %v. Proxy Addr: %v", req.RedirectURL, a.s.getProxyPublicAddr())
	err = a.s.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

func (a *OIDCAuthService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*OIDCAuthResponse, error) {
	diagCtx := NewSSODiagContext(types.KindOIDC, a.s)

	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method: events.LoginMethodOIDC,
	}

	auth, err := a.validateOIDCAuthCallback(ctx, diagCtx, q)
	diagCtx.Info.Error = trace.UserMessage(err)
	event.AppliedLoginRules = diagCtx.Info.AppliedLoginRules

	diagCtx.WriteToBackend(ctx)

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()

		if err := a.s.emitter.EmitAuditEvent(ctx, event); err != nil {
			log.WithError(err).Warn("Failed to emit OIDC login failed event.")
		}
		return nil, trace.Wrap(err)
	}
	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.Status.Success = true
	event.User = auth.Username

	if err := a.s.emitter.EmitAuditEvent(ctx, event); err != nil {
		log.WithError(err).Warn("Failed to emit OIDC login event.")
	}

	return auth, nil
}

type RawIDTokenClaims map[string]interface{}

func (a *OIDCAuthService) validateOIDCAuthCallback(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*OIDCAuthResponse, error) {

	log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf("Validating OIDC callback")

	if errParam := q.Get("error"); errParam != "" {
		// try to find request so the error gets logged against it.
		state := q.Get("state")
		if state != "" {
			diagCtx.RequestID = state
			req, err := a.s.Services.GetOIDCAuthRequest(ctx, state)
			if err == nil {
				diagCtx.Info.TestFlow = req.SSOTestFlow
			}
		}

		// optional parameter: error_description
		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2("oauth2InvalidRequest", errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "GitHub returned error: %v [%v]", errDesc, errParam)
	}

	code := q.Get("code")
	if code == "" {
		oauthErr := trace.OAuth2("oauth2InvalidRequest", "code query param must be set", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from OIDC.")
	}

	stateToken := q.Get("state")
	if stateToken == "" {
		oauthErr := trace.OAuth2("oauth2InvalidRequest", "missing state query param", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from OIDC.")
	}
	diagCtx.RequestID = stateToken

	log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf("Got code and state")

	req, err := a.s.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC Auth Request.")
	}
	diagCtx.Info.TestFlow = req.SSOTestFlow

	connector, err := a.s.GetOIDCConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	p, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	redirectURL, err := services.GetRedirectURL(connector, a.s.getProxyPublicAddr())

	oauthConfig := oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		Endpoint:     p.Endpoint(),
		Scopes:       connector.GetScope(),
		RedirectURL:  redirectURL,
	}

	oauth2Token, err := oauthConfig.Exchange(ctx, code)

	if err != nil {
		return nil, trace.Wrap(err)
	}

	log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf("Exchanged OIDC code successfully")

	oidcConfig := &oidc.Config{
		ClientID: connector.GetClientID(),
	}
	verifier := p.Verifier(oidcConfig)

	if err != nil {
		return nil, trace.Wrap(err, fmt.Sprintf("Failed to verify code: %s", err))
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, trace.Wrap(err, fmt.Sprintf("No id_token in oauth response: %s", err))
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, trace.Wrap(err, fmt.Sprintf("Failed to verify id token: %s", err))
	}

	var rawClaims RawIDTokenClaims
	if err = idToken.Claims(&rawClaims); err != nil {
		return nil, trace.Wrap(err, fmt.Sprintf("Failed to extract id token claims: %s", err))
	}

	// Check for distributed claims
	distributedClaims, hasDistribClaims := rawClaims["_claim_names"].(map[string]string)
	claimSources, hasClaimSources := rawClaims["_claim_sources"].(map[string]interface{})
	if hasDistribClaims && hasClaimSources {
		log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf("ID Token has distributed claims - resolving")
		for distribClaimName, distribClaimSourceName := range distributedClaims {
			claimSource, sourceExists := claimSources[distribClaimSourceName].(map[string]interface{})
			if sourceExists {
				endpoint, epe := claimSource["endpoint"].(string)
				accessToken := claimSource["access_token"].(string)

				if epe {
					claims, err := resolveDistributedClaim(ctx, verifier, endpoint, accessToken)

					if err == nil {
						log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf("Resolved distributed claims %v", claims)
						rawClaims[distribClaimName] = claims
					} else {
						log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf("Failed to resolve distributed claims %v", err)
					}
				}
			}
		}
	}

	username, ok := rawClaims["preferred_username"].(string)
	if !ok {
		username, ok = rawClaims["email"].(string)
	}

	params, err := a.s.calculateOIDCUser(ctx, diagCtx, connector, username, rawClaims, req)

	if err != nil {
		return nil, trace.Wrap(err, fmt.Sprintf("Failed to calculateOIDCUser: %s", err))
	}

	diagCtx.Info.CreateUserParams = &types.CreateUserParams{
		ConnectorName: params.ConnectorName,
		Username:      params.Username,
		KubeGroups:    params.KubeGroups,
		KubeUsers:     params.KubeUsers,
		Roles:         params.Roles,
		Traits:        params.Traits,
		SessionTTL:    types.Duration(params.SessionTTL),
	}

	user, err := a.s.createOIDCUser(ctx, params, req.SSOTestFlow)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to create user from provided parameters.")
	}

	if err := a.s.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	userState, err := a.s.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Auth was successful, return session, certificate, etc. to caller.
	auth := OIDCAuthResponse{
		Req: OIDCAuthRequestFromProto(req),
		Identity: types.ExternalIdentity{
			ConnectorID: params.ConnectorName,
			Username:    params.Username,
		},
		Username: user.GetName(),
	}

	// In test flow skip signing and creating web sessions.
	if req.SSOTestFlow {
		diagCtx.Info.Success = true
		return &auth, nil
	}

	// If the request is coming from a browser, create a web session.
	if req.CreateWebSession {
		session, err := a.s.CreateWebSessionFromReq(ctx, types.NewWebSessionRequest{
			User:             userState.GetName(),
			Roles:            userState.GetRoles(),
			Traits:           userState.GetTraits(),
			SessionTTL:       params.SessionTTL,
			LoginTime:        a.s.clock.Now().UTC(),
			LoginIP:          req.ClientLoginIP,
			AttestWebSession: true,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create web session.")
		}

		auth.Session = session
	}

	// If a public key was provided, sign it and return a certificate.
	if len(req.PublicKey) != 0 {
		sshCert, tlsCert, err := a.s.CreateSessionCert(userState, params.SessionTTL, req.PublicKey, req.Compatibility, req.RouteToCluster,
			req.KubernetesCluster, req.ClientLoginIP, keys.AttestationStatementFromProto(req.AttestationStatement))
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create session certificate.")
		}

		clusterName, err := a.s.GetClusterName()
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster name.")
		}

		auth.Cert = sshCert
		auth.TLSCert = tlsCert

		// Return the host CA for this cluster only.
		authority, err := a.s.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster's host CA.")
		}
		auth.HostSigners = append(auth.HostSigners, authority)
	}

	return &auth, nil
}

func (a *Server) calculateOIDCUser(ctx context.Context, diagCtx *SSODiagContext, connector types.OIDCConnector, username string, claims RawIDTokenClaims, request *types.OIDCAuthRequest) (*CreateUserParams, error) {
	p := CreateUserParams{
		ConnectorName: connector.GetName(),
		Username:      username,
	}

	claimToRoles := connector.GetClaimsToRoles()

	for _, claimMap := range claimToRoles {

		v, stringOK := claims[claimMap.Claim].(string)
		if stringOK {
			if v == claimMap.Value {
				for _, r := range claimMap.Roles {
					if !slices.Contains(p.Roles, r) {
						p.Roles = append(p.Roles, r)
					}
				}
			}
		}

		vs, mapOK := claims[claimMap.Claim].([]interface{})
		if mapOK {
			for _, claimVal := range vs {
				claimValString, claimValIsString := claimVal.(string)
				if claimValIsString {
					if claimValString == claimMap.Value {
						for _, r := range claimMap.Roles {
							if !slices.Contains(p.Roles, r) {
								p.Roles = append(p.Roles, r)
							}
						}
					}
				}
			}
		}
	}

	var loginTrait = username
	if at := strings.LastIndex(username, "@"); at >= 0 {
		loginTrait = username[at:]
	}

	if len(p.Roles) == 0 {
		log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf("Couldn't retrieve OIDC roles from claims: %v", claims)
		return nil, trace.Wrap(ErrOIDCNoRoles)
	}
	p.Traits = map[string][]string{
		constants.TraitLogins:        {loginTrait},
		constants.TraitWindowsLogins: {loginTrait},
		constants.TraitKubeGroups:    p.KubeGroups,
		constants.TraitKubeUsers:     p.KubeUsers,
	}

	for claimName, claim := range claims {

		if slices.Contains(ExternalSkippedClaims, claimName) {
			continue
		}

		v, stringOK := claim.(string)
		if stringOK {
			//p.Traits[fmt.Sprintf("%s.%s", teleport.TraitExternalPrefix, claimName)] = []string{v}
			p.Traits[claimName] = []string{v}
			continue
		}

		vm, mapOK := claim.([]interface{})
		if mapOK {
			var stringSlice []string
			for _, claimVal := range vm {
				v, stringOK = claimVal.(string)
				if stringOK {
					stringSlice = append(stringSlice, v)
				}
			}

			//p.Traits[fmt.Sprintf("%s.%s", teleport.TraitExternalPrefix, claimName)] = stringSlice
			p.Traits[claimName] = stringSlice
		}
	}

	evaluationInput := &loginrule.EvaluationInput{
		Traits: p.Traits,
	}
	evaluationOutput, err := a.GetLoginRuleEvaluator().Evaluate(ctx, evaluationInput)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	p.Traits = evaluationOutput.Traits
	diagCtx.Info.AppliedLoginRules = evaluationOutput.AppliedRules

	// Kube groups and users are ultimately only set in the traits, not any
	// other property of the User. In case the login rules changed the relevant
	// traits values, reset the value on the user params for accurate
	// diagnostics.
	p.KubeGroups = p.Traits[constants.TraitKubeGroups]
	p.KubeUsers = p.Traits[constants.TraitKubeUsers]

	// Pick smaller for role: session TTL from role or requested TTL.
	roles, err := services.FetchRoles(p.Roles, a, p.Traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := roles.AdjustSessionTTL(apidefaults.MaxCertDuration)
	p.SessionTTL = utils.MinTTL(roleTTL, request.CertTTL)

	return &p, nil
}

func (a *Server) createOIDCUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	log.WithFields(logrus.Fields{trace.Component: "oidc"}).Debugf(
		"Generating dynamic OIDC identity %v/%v with roles: %v. Dry run: %v.",
		p.ConnectorName, p.Username, p.Roles, dryRun)

	expires := a.GetClock().Now().UTC().Add(p.SessionTTL)

	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.Username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.Roles,
			Traits: p.Traits,
			OIDCIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: a.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.OIDC,
					ID:       p.ConnectorName,
					Identity: p.Username,
				},
			},
		},
	}

	if dryRun {
		return user, nil
	}

	existingUser, err := a.Services.GetUser(ctx, p.Username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not an OIDC user",
				existingUser.GetName())
		}

		user.SetRevision(existingUser.GetRevision())
		if _, err := a.Services.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if _, err := a.Services.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}

func OIDCAuthRequestFromProto(req *types.OIDCAuthRequest) OIDCAuthRequest {
	return OIDCAuthRequest{
		ConnectorID:       req.ConnectorID,
		PublicKey:         req.PublicKey,
		CSRFToken:         req.CSRFToken,
		CreateWebSession:  req.CreateWebSession,
		ClientRedirectURL: req.ClientRedirectURL,
	}
}

func resolveDistributedClaim(ctx context.Context, verifier *oidc.IDTokenVerifier, endpoint string, accessToken string) (RawIDTokenClaims, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("malformed request: %v", err)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)

	if !ok {
		return nil, fmt.Errorf("could not retrieve http client: %v", err)
	}

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("oidc: Request to endpoint failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: request failed: %v", resp.StatusCode)
	}

	token, err := verifier.Verify(ctx, string(body))
	if err != nil {
		return nil, fmt.Errorf("malformed response body: %v", err)
	}

	var rawClaims RawIDTokenClaims
	if err := token.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("failed to extract token claims: %v", err)
	}

	return rawClaims, nil
}
