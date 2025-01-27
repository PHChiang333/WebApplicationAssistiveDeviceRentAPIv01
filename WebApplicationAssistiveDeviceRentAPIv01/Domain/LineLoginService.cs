using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Runtime.Remoting.Channels;
using System.Threading.Tasks;
using System.Web;
using WebApplicationAssistiveDeviceRentAPIv01.Models.Dto;
using WebApplicationAssistiveDeviceRentAPIv01.Providers;

namespace WebApplicationAssistiveDeviceRentAPIv01.Domain
{
    public class LineLoginService
    {
        private static HttpClient client = new HttpClient();
        private readonly JsonProvider _jsonProvider = new JsonProvider();

        public LineLoginService()
        {
        }


        //----------------------------------------------------------------------------------------------------------------------------------

        private readonly string loginUrl = "https://access.line.me/oauth2/v2.1/authorize?response_type={0}&client_id={1}&redirect_uri={2}&state={3}&scope={4}";
        private readonly string clientId = "2006800464";
        private readonly string clientSecret = "11a4b5ba4a4913d2619ebcc41b5c2ca2";

        // 回傳 line authorization url
        public string GetLoginUrl(string redirectUrl)
        {
            // 根據想要得到的資訊填寫 scope
            var scope = "profile%20openid%20email";
            // 這個 state 是隨便打的
            var state = "1qazRTGFDY5ysg";
            var uri = string.Format(loginUrl, "code", clientId, HttpUtility.UrlEncode(redirectUrl), state, scope);
            return uri;
        }


        //----------------------------------------------------------------------------------------------------------------------------------
        //https://api.line.me/oauth2/v2.1/token

        private readonly string tokenUrl = "https://api.line.me/oauth2/v2.1/token";


        // 取得 access token 等資料
        public async Task<TokensResponseDto> GetTokensByAuthToken(string authToken, string callbackUri)
        {
            var formContent = new FormUrlEncodedContent(new[]
            {
        new KeyValuePair<string, string>("grant_type", "authorization_code"),
        new KeyValuePair<string, string>("code", authToken),
        new KeyValuePair<string, string>("redirect_uri",callbackUri),
        new KeyValuePair<string, string>("client_id", clientId),
        new KeyValuePair<string, string>("client_secret", clientSecret),
    });

            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json")); //添加 accept header
            var response = await client.PostAsync(tokenUrl, formContent); // 送出 post request
            var dto = _jsonProvider.Deserialize<TokensResponseDto>(await response.Content.ReadAsStringAsync()); //將 json response 轉成 dto

            return dto;
        }



        //----------------------------------------------------------------------------------------------------------------------------------
        //https://api.line.me/v2/profile

        private readonly string profileUrl = "https://api.line.me/v2/profile";


        public async Task<UserProfileLineDto> GetUserProfileByAccessToken(string accessToken)
        {
            //取得 UserProfile
            var request = new HttpRequestMessage(HttpMethod.Get, profileUrl);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var response = await client.SendAsync(request);
            var profile = _jsonProvider.Deserialize<UserProfileLineDto>(await response.Content.ReadAsStringAsync());

            return profile;
        }



        //----------------------------------------------------------------------------------------------------------------------------------





    }
}