using System;
using System.Threading.Tasks;
using Qlik.OAuthManager;

namespace AuthenticateInBrowser
{
	internal class Program
	{
		static async Task Main(string[] args)
		{
			var tenantUrl = "<tenant>";
			var clientId = "<client_id>";
			var redirectUri = "<url>"; // Example: http://localhost:8123

			var oauthManager = new OAuthManager(tenantUrl, clientId);
			await oauthManager.AuthorizeInBrowser("user_default offline_access", redirectUri, Browser.Default);

			var accessToken = await oauthManager.RequestNewAccessToken();
			Console.WriteLine("Access token:  " + accessToken);
			Console.WriteLine("Refresh token: " + oauthManager.RefreshToken);
			Console.WriteLine(oauthManager.FullTokenResponse.ToString());
			accessToken = await oauthManager.RequestNewAccessToken();
			Console.WriteLine("Access token:  " + accessToken);
			Console.WriteLine("Refresh token: " + oauthManager.RefreshToken);
			Console.WriteLine(oauthManager.FullTokenResponse.ToString());
		}
	}
}