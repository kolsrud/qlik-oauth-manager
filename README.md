# qlik-oauth-manager
Library for using QCS OAuth clients to produce access tokens. Such tokens can in turn be used as API keys when
configuring connections with the libraries `QlikSense.NetSDK` and `QlikSenseRestClient`. A flow to produce an
access token could look like this:

    var oauthManager = new OAuthManager(tenantUrl, clientId);
    await oauthManager.AuthorizeInBrowser("user_default offline_access", redirectUri, Browser.Default);
    var accessToken = await oauthManager.RequestNewAccessToken();

The resulting access token can then be used with the library `QlikSense.NetSDK` to connect to the engine like this:

    var location = QcsLocation.FromUri(tenantUrl);
    location.AsApiKey(accessToken);
    
    using (var app = await location.AppAsync(appId))
    {
        Console.WriteLine((await app.GetAppPropertiesAsync()).Title);
    }

Or the token can be used to connect using the library `QlikSenseRestClient` like this:

    var client = new RestClient(tenantUrl);
    client.AsApiKeyViaQcs(accessToken);
    Console.WriteLine(await client.GetAsync<JToken>("/api/v1/users/me"));