using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Qlik.OAuthManager
{

	public enum Browser
	{
		Default,
		Chrome,
		Firefox,
		MSEdge
	}

	public interface IOAuthManager
	{
		string AuthorizationResponsePage { get; set; }
		string AccessToken { get; }
		string RefreshToken { get; }
		JObject FullTokenResponse { get; }

		Task AuthorizeInBrowser(string scope, string redirectUri);
		Task AuthorizeInBrowser(string scope, string redirectUri, Browser browser);
		Task AuthorizeInBrowser(string scope, string redirectUri, string pathToBrowserExe);
		Task AuthorizeInBrowser(string scope, string redirectUri, CancellationToken cancellationToken);
		Task AuthorizeInBrowser(string scope, string redirectUri, Browser browser, CancellationToken cancellationToken);
		Task AuthorizeInBrowser(string scope, string redirectUri, string pathToBrowserExe, CancellationToken cancellationToken);
		Task<string> RequestNewAccessToken();
		Task<string> RequestNewAccessToken(string clientSecret);
		Task<string> RequestNewAccessToken(string clientSecret, string subject);
	}

	public class OAuthManager : IOAuthManager
	{
		private const string StyleDefinition = "<style>h1 {text-align: center;}p {text-align: center;}</style>";
		private const string Body = "<h1>Authentication Complete</h1><p>You can close this tab.<p>";
		private const string DefaultAuthorizationResponsePage = "<HTML>" + StyleDefinition + "<BODY>" + Body + "</BODY></HTML>";

		public string AuthorizationResponsePage { get; set; } = DefaultAuthorizationResponsePage;
		public string AccessToken => FullTokenResponse?["access_token"]?.Value<string>();
		public string RefreshToken => FullTokenResponse?["refresh_token"]?.Value<string>();
		public JObject FullTokenResponse { get; private set; }

		private readonly Lazy<HttpClient> _httpClient = new Lazy<HttpClient>(() => new HttpClient());

		private readonly Uri _tenantUrl;
		private readonly string _clientId;
		private readonly Code _code = new Code();
		private string _authorizationCode;
		private string _redirectUri;

		public OAuthManager(string tenantUrl, string clientId) : this(new Uri(tenantUrl), clientId)
		{
		}

		public OAuthManager(Uri tenantUrl, string clientId)
		{
			_tenantUrl = tenantUrl;
			_clientId = clientId;
		}

		public Task AuthorizeInBrowser(string scope, string redirectUri)
		{
			return AuthorizeInBrowser(scope, redirectUri, new CancellationToken());
		}

		public Task AuthorizeInBrowser(string scope, string redirectUri, Browser browser)
		{
			return AuthorizeInBrowser(scope, redirectUri, browser, new CancellationToken());
		}

		public Task AuthorizeInBrowser(string scope, string redirectUri, string pathToBrowserExe)
		{
			return AuthorizeInBrowser(scope, redirectUri, pathToBrowserExe, new CancellationToken());
		}

		public Task AuthorizeInBrowser(string scope, string redirectUri, CancellationToken cancellationToken)
		{
			return AuthorizeInBrowser(scope, redirectUri, null, cancellationToken);
		}

		public Task AuthorizeInBrowser(string scope, string redirectUri, Browser browser, CancellationToken cancellationToken)
		{
			return AuthorizeInBrowser(scope, redirectUri, browser == Browser.Default ? null : browser.ToString().ToLower(), cancellationToken);
		}

		public async Task AuthorizeInBrowser(string scope, string redirectUri, string pathToBrowserExe, CancellationToken cancellationToken)
		{
			var state = Guid.NewGuid().ToString();
			var query = new[]
			{
				("response_type", "code"),
				("client_id", _clientId),
				("redirect_uri", redirectUri),
				("scope", scope),
				("state", state),
				("code_challenge", _code.CodeChallenge),
				("code_challenge_method", "S256")
			};
			var builder = new UriBuilder(_tenantUrl)
			{
				Path = "oauth/authorize",
				Query = string.Join("&", query.Select(arg => arg.Item1 + "=" + Uri.EscapeDataString(arg.Item2)))
			};
			var url = builder.Uri.AbsoluteUri;
			var processStartInfo = pathToBrowserExe == null
				? new ProcessStartInfo(builder.Uri.ToString()) { UseShellExecute = true }
				: new ProcessStartInfo(pathToBrowserExe, url) { UseShellExecute = true };

			var callbackHandler = new HttpOAuthCallbackHandler(new Uri(redirectUri), AuthorizationResponsePage);
			using (Process.Start(processStartInfo))
			{
				_authorizationCode = await callbackHandler.GetResponse(cancellationToken).ConfigureAwait(false);
			}

			_redirectUri = redirectUri;
		}

		public Task<string> RequestNewAccessToken()
		{
			if (_authorizationCode == null)
				throw new InvalidOperationException(
					"Token request must be preceded by authorization call when no client secret is specified.");

			return RefreshToken == null ? RequestAccessToken() : RefreshAccessToken();
		}

		public async Task<string> RequestNewAccessToken(string clientSecret)
		{
			var body = JObject.FromObject(new
			{
				scope = "user_default",
				grant_type = "client_credentials",
			});

			FullTokenResponse = await Post("oauth/token", body, clientSecret).ConfigureAwait(false);
			return AccessToken;
		}

		public async Task<string> RequestNewAccessToken(string clientSecret, string subject)
		{
			var body = JObject.FromObject(new
			{
				scope = "user_default",
				grant_type = "urn:qlik:oauth:user-impersonation",
				user_lookup = new
				{
					field = "subject",
					value = subject
				}
			});
			FullTokenResponse = await Post("oauth/token", body, clientSecret).ConfigureAwait(false);
			return AccessToken;
		}

		private async Task<string> RequestAccessToken()
		{
			var body = JObject.FromObject(new
			{
				client_id = _clientId,
				code_verifier = _code.CodeVerifier,
				grant_type = "authorization_code",
				code = _authorizationCode,
				redirect_uri = _redirectUri
			});

			FullTokenResponse = await Post("oauth/token", body).ConfigureAwait(false);
			return AccessToken;
		}

		private async Task<string> RefreshAccessToken()
		{
			var body = JObject.FromObject(new
			{
				grant_type = "refresh_token",
				refresh_token = RefreshToken
			});

			FullTokenResponse = await Post("oauth/token", body).ConfigureAwait(false);
			return AccessToken;
		}

		private async Task<JObject> Post(string endpoint, JObject body, string clientSecret = null)
		{
			var mContent = new StringContent(body.ToString(), Encoding.ASCII, "application/json");
			mContent.Headers.ContentType = new MediaTypeWithQualityHeaderValue("application/json");
			var builder = new UriBuilder(_tenantUrl) { Path = endpoint };
			var message = new HttpRequestMessage(HttpMethod.Post, builder.Uri.AbsoluteUri) { Content = mContent };
			if (clientSecret != null)
				message.Headers.Authorization =
					new AuthenticationHeaderValue("Basic", Base64Encode($"{_clientId}:{clientSecret}"));
			var rspHttp = await _httpClient.Value.SendAsync(message).ConfigureAwait(false);
			return JObject.Parse(await rspHttp.Content.ReadAsStringAsync().ConfigureAwait(false));
		}

		private static string Base64Encode(string plainText)
		{
			var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
			return System.Convert.ToBase64String(plainTextBytes);
		}
	}

	internal class Code
	{
		public readonly string CodeVerifier;
		public readonly string CodeChallenge;

		public Code()
		{
			CodeVerifier = GenerateNonce();
			CodeChallenge = GenerateCodeChallenge(CodeVerifier);
		}

		public static string GenerateNonce()
		{
			const string chars = "abcdefghijklmnopqrstuvwxyz123456789";
			var random = new Random();
			var nonce = new char[128];
			for (int i = 0; i < nonce.Length; i++)
			{
				nonce[i] = chars[random.Next(chars.Length)];
			}

			return new string(nonce);
		}

		private static string GenerateCodeChallenge(string codeVerifier)
		{
			using (var sha256 = SHA256.Create())
			{
				var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
				var b64Hash = Convert.ToBase64String(hash);
				var code = Regex.Replace(b64Hash, "\\+", "-");
				code = Regex.Replace(code, "\\/", "_");
				code = Regex.Replace(code, "=+$", "");
				return code;
			}
		}
	}
}