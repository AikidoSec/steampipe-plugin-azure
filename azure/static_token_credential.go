package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// staticTokenCredential is an azcore.TokenCredential that always returns the same
// pre-fetched access token.
type staticTokenCredential string

func (c staticTokenCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: string(c)}, nil
}

// staticOAuthTokenProvider is an adal.OAuthTokenProvider (used by the legacy
// go-autorest BearerAuthorizer) over the same pre-fetched access token.
type staticOAuthTokenProvider string

func (t staticOAuthTokenProvider) OAuthToken() string {
	return string(t)
}
