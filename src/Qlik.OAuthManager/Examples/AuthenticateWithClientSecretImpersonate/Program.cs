using System;
using System.Threading.Tasks;
using Qlik.OAuthManager;

namespace AuthenticateWithClientSecretImpersonate
{
	internal class Program
	{
		static async Task Main(string[] args)
		{
			var tenantUrl = "<tenant>";
			var clientId = "<client_id>";
			var clientSecret = "<client_secret>";
			var subject = "<subject>";

			IOAuthManager oauthManager = new OAuthManager(tenantUrl, clientId);

			var accessToken = await oauthManager.RequestNewAccessToken(clientSecret, subject);
			Console.WriteLine("Access token:  " + accessToken);
			Console.WriteLine("Refresh token: " + (oauthManager.RefreshToken ?? "<null>"));
			Console.WriteLine(oauthManager.FullTokenResponse.ToString());
		}
	}
}