package auth

import (
	"encoding/json"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

/*
validateOIDCAuthCallback validates OIDC auth callback redirect

	POST /:version/oidc/requests/validate

	Success response: oidcAuthRawResponse
*/
func (s *APIServer) validateOIDCAuthCallback(auth *ServerWithRoles, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req validateGithubAuthCallbackReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	response, err := auth.ValidateOIDCAuthCallback(r.Context(), req.Query)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	raw := OIDCAuthRawResponse{
		Username: response.Username,
		Identity: response.Identity,
		Cert:     response.Cert,
		TLSCert:  response.TLSCert,
		Req:      response.Req,
	}
	if response.Session != nil {
		rawSession, err := services.MarshalWebSession(
			response.Session, services.WithVersion(version), services.PreserveResourceID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		raw.Session = rawSession
	}
	raw.HostSigners = make([]json.RawMessage, len(response.HostSigners))
	for i, ca := range response.HostSigners {
		data, err := services.MarshalCertAuthority(
			ca, services.WithVersion(version), services.PreserveResourceID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		raw.HostSigners[i] = data
	}
	return &raw, nil
}
