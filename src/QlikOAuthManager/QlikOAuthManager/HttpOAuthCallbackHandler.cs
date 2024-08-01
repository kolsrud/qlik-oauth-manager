using System.Net;

namespace QlikOAuthManager;

public class HttpOAuthCallbackHandler
{
	private readonly string _authorizationResponsePage;
	private readonly Uri _url;

	public HttpOAuthCallbackHandler(Uri url, string authorizationResponsePage)
	{
		_authorizationResponsePage = authorizationResponsePage;
		_url = url;
	}

	public async Task<string> GetResponse()
	{
		using (var listener = new HttpListener())
		{
			listener.Prefixes.Add(_url.AbsoluteUri);
			listener.Start();
			var completionSource = new TaskCompletionSource<string>();
			listener.BeginGetContext(result => ListenerCallback(listener.EndGetContext(result), completionSource), listener);
			try
			{
				return await completionSource.Task;
			}
			finally
			{
				listener.Stop();
			}
		}
	}

	private void ListenerCallback(HttpListenerContext context, TaskCompletionSource<string> completionSource)
	{
		var request = context.Request;

		var query = System.Web.HttpUtility.ParseQueryString(request.Url.Query);
		var code = query.Get("code");

		var response = context.Response;
		response.StatusCode = (int)HttpStatusCode.OK;
		response.ContentType = "text/html";
		byte[] buffer = System.Text.Encoding.UTF8.GetBytes(_authorizationResponsePage);
		response.ContentLength64 = buffer.Length;
		response.OutputStream.Write(buffer, 0, buffer.Length);
		response.OutputStream.Close();
		if (code != null)
			completionSource.SetResult(code);
		else
			completionSource.SetException(new Exception("Callback does not contain the argument \"code\"."));
	}
}