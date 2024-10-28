using System;
using System.Threading.Tasks;
using Qlik.OAuthManager;

namespace AuthenticateWithRefreshToken
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var tenantUrl = "<tenant>";
            var clientId = "<client_id>";
            var refreshToken = "<refresh_token>";

            IOAuthManager oauthManager = new OAuthManager(tenantUrl, clientId);
            
            var accessToken = await oauthManager.RefreshAccessToken(refreshToken);
            Console.WriteLine("Access token:  " + accessToken);
            Console.WriteLine("Refresh token: " + oauthManager.RefreshToken);
            Console.WriteLine(oauthManager.FullTokenResponse.ToString());
        }
    }
}
