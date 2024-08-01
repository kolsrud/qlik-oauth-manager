using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;
using Microsoft.VisualBasic.CompilerServices;
using Newtonsoft.Json.Linq;

namespace QlikOAuthManager;

public enum Browser
{
	Default,
	Chrome,
	Firefox,
	MSEdge
}

public class OAuthManager
{
	private const string DefaultAuthorizationResponsePage = "<HTML><style>h1 {text-align: center;}p {text-align: center;}</style><BODY><h1>Authentication complete</h1><p>You can close this tab.</p></BODY></HTML>";

	public string AuthorizationResponsePage { get; set; } = DefaultAuthorizationResponsePage;
	public string? AccessToken => FullTokenResponse?["access_token"]?.Value<string>();
	public string? RefreshToken => FullTokenResponse?["refresh_token"]?.Value<string>();
	public JObject? FullTokenResponse { get; private set; }
	private readonly Lazy<HttpClient> _httpClient = new Lazy<HttpClient>(() => new HttpClient());

	private readonly string _tenantUrl;
	private readonly string _clientId;
	private readonly string _clientSecret;
	private readonly Code _code = new Code();
	private string _authorizationCode;
	private string _redirectUri;

	public OAuthManager(string tenantUrl, string clientId)
	{
		_tenantUrl = tenantUrl;
		_clientId = clientId;
	}

	public OAuthManager(string tenantUrl, string clientId, string clientSecret)
	{
		_tenantUrl = tenantUrl;
		_clientId = clientId;
		_clientSecret = clientSecret;
	}

	public Task AuthorizeInBrowser(string scope, string redirectUri, Browser browser)
	{
		return AuthorizeInBrowser(scope, redirectUri, browser == Browser.Default ? null : browser.ToString().ToLower());
	}

	public async Task AuthorizeInBrowser(string scope, string redirectUri, string? pathToBrowserExe = null)
	{
		var state = Guid.NewGuid().ToString();
		Console.WriteLine(redirectUri);
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
		Console.WriteLine(url);
		var processStartInfo = pathToBrowserExe == null
			? new ProcessStartInfo(builder.Uri.ToString()) { UseShellExecute = true }
			: new ProcessStartInfo(pathToBrowserExe, url) { UseShellExecute = true };

		var callbackHandler = new HttpOAuthCallbackHandler(new Uri(redirectUri), AuthorizationResponsePage);
		using (Process.Start(processStartInfo))
		{
			_authorizationCode = await callbackHandler.GetResponse();
		}

		_redirectUri = redirectUri;
	}

	public async Task<string> RequestNewAccessToken(string clientSecret)
	{
		var body = JObject.FromObject(new
		{
			scope = "user_default",
			grant_type = "client_credentials",
		});

		FullTokenResponse = await Post("oauth/token", body, clientSecret);
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
		FullTokenResponse = await Post("oauth/token", body, clientSecret);
		return AccessToken;
	}

	public async Task<string> RequestNewAccessToken()
	{
		if (_authorizationCode == null)
			throw new InvalidOperationException("Token request must be preceded by authorization call when no client secret is specified.");

		if (RefreshToken == null)
		{
			await RequestAccessToken();
		}
		else
		{
			await RefreshAccessToken();
		}
		return AccessToken;
	}

	private async Task RequestAccessToken()
	{
		var body = JObject.FromObject(new
		{
			client_id = _clientId,
			code_verifier = _code.CodeVerifier,
			grant_type = "authorization_code",
			code = _authorizationCode,
			redirect_uri = _redirectUri
		});

		FullTokenResponse = await Post("oauth/token", body);
	}

	private async Task RefreshAccessToken()
	{
		var body = JObject.FromObject(new
		{
			grant_type = "refresh_token",
			refresh_token = RefreshToken
		});

		FullTokenResponse = await Post("oauth/token", body);
	}

	private async Task<JObject> Post(string endpoint, JObject body, string clientSecret = null)
	{
		var mContent = new StringContent(body.ToString(), Encoding.ASCII, "application/json");
		mContent.Headers.ContentType = new MediaTypeWithQualityHeaderValue("application/json");
		
		var message = new HttpRequestMessage(HttpMethod.Post, _tenantUrl + endpoint) { Content = mContent };
		if (clientSecret != null)
			message.Headers.Authorization = new AuthenticationHeaderValue("Basic", Base64Encode($"{_clientId}:{clientSecret}"));
		var rspHttp = await _httpClient.Value.SendAsync(message);
		return JObject.Parse(await rspHttp.Content.ReadAsStringAsync());
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
