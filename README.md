# qlik-oauth-manager
Library for using QCS OAuth clients to produce access tokens. The tokens can be used with both of the
libraries `QlikSense.NetSDK` and `QlikSenseRestClient`. The access token can be used as an API key when
connecting. A flow to produce an access token could look like this:

    var oauthManager = new OAuthManager(tenantUrl, clientId);
    await oauthManager.AuthorizeInBrowser("user_default offline_access", redirectUri, Browser.Default);
    var accessToken = await oauthManager.RequestNewAccessToken();

The resulting access token can then be use with the library `QlikSense.NetSDK` to connect to the engine like this:

    var location = QcsLocation.FromUri(tenantUrl);
    location.AsApiKey(accessToken);
    
    using (var app = await location.AppAsync(appId))
    {
      Console.WriteLine((await app.GetAppPropertiesAsync()).Title);
    }

Or the key can be use to connect using the `QlikSenseRestClient` like this:

    var client = new RestClient(tenantUrl);
    client.AsApiKeyViaQcs(accessToken);
    Console.WriteLine(await client.GetAsync<JToken>("/api/v1/users/me"));