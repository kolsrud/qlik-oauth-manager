using Qlik.OAuthManager;

namespace AuthenticateWithClientSecret;

internal class Program
{
	static async Task Main(string[] args)
	{
		var tenantUrl = "<tenant>";
		var clientId = "<client_id>";
		var clientSecret = "<client_secret>";

		var oauthManager = new OAuthManager(tenantUrl, clientId);

		var accessToken = await oauthManager.RequestNewAccessToken(clientSecret);
		Console.WriteLine("Access token:  " + accessToken);
		Console.WriteLine("Refresh token: " + oauthManager.RefreshToken);
		Console.WriteLine(oauthManager.FullTokenResponse.ToString());
	}
}
