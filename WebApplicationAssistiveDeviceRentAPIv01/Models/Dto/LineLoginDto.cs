using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models.Dto
{
    public class LineLoginDto
    {
    }

    public class LineCallbackModel
    {
        public string Code { get; set; }
        public string State { get; set; }
    }

    public class LineTokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("id_token")]
        public string IdToken { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonProperty("scope")]
        public string Scope { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }
    }

    public class LineProfileResponse
    {
        [JsonProperty("userId")]
        public string UserId { get; set; }

        [JsonProperty("displayName")]
        public string DisplayName { get; set; }

        [JsonProperty("pictureUrl")]
        public string PictureUrl { get; set; }
    }


    public class LineProfileByIdTokenResponse
    {


    }



    // 參考

    public class TokensResponseDto
    {
        public string Access_token { get; set; }
        public string Token_type { get; set; }
        public string Refresh_token { get; set; }
        public int Expires_in { get; set; }
        public string Scope { get; set; }
        public string Id_token { get; set; }
    }


    /// <summary>
    /// 會和本來的 UserProfileDto 混淆
    /// 改為 UserProfileLineDto
    /// </summary>
    public class UserProfileLineDto  
    {
        public string UserId { get; set; }
        public string DisplayName { get; set; }
        public string StatusMessage { get; set; }
        public string PictureUrl { get; set; }
    }





}