using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Qlik.OAuthManager
{
	internal class HttpOAuthCallbackHandler
	{
		private readonly string _authorizationResponsePage;
		private readonly Uri _url;

		public HttpOAuthCallbackHandler(Uri url, string authorizationResponsePage)
		{
			_authorizationResponsePage = authorizationResponsePage;
			_url = url;
		}

		public async Task<string> GetResponse(CancellationToken cancellationToken)
		{
			using (var listener = new HttpListener())
			{
				listener.Prefixes.Add(_url.AbsoluteUri);
				listener.Start();
				var completionSource = new TaskCompletionSource<string>();

				listener.BeginGetContext(result => ListenerCallback(listener, result, completionSource), listener);
				try
				{
					using (cancellationToken.Register(() => { completionSource.TrySetCanceled(); }))
					{
						return await completionSource.Task.ConfigureAwait(false);
					}
				}
				finally
				{
					listener.Stop();
					listener.Close();
				}
			}
		}

		private void ListenerCallback(HttpListener listener, IAsyncResult asyncResult, TaskCompletionSource<string> completionSource)
		{
			if (completionSource.Task.IsCompleted)
				return;

			var context = listener.EndGetContext(asyncResult);
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
}