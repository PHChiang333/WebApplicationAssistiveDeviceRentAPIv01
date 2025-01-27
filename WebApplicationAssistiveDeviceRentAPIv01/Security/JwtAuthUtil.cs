using Jose;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Configuration;

namespace WebApplicationAssistiveDeviceRentAPIv01.Security
{
    public class JwtAuthUtil
    {
        //private readonly ApplicationDbContext db = new ApplicationDbContext(); // DB 連線

        private static readonly string secretKey = "TokenKey";



        /// <summary>
        /// 生成 JwtToken
        /// </summary>
        /// <param name="UserId">會員UserId</param>
        /// <returns>JwtToken</returns>
        public string GenerateToken(int UserId)
        {
            // 自訂字串，驗證用，用來加密送出的 key (放在 Web.config 的 appSettings)
            /*  string secretKey = WebConfigurationManager.AppSettings["TokenKey"]; */// 從 appSettings 取出
            //var user = db.User.Find(id); // 進 DB 取出想要夾帶的基本資料
            //----------------------------------
            //改為不用再跟DB連線，可以在登入階段撈data就好
            //string secretKey = "ILoveRocketCoding";  //私鑰
            string secretKey = "TokenKey";  //私鑰

            // payload 需透過 token 傳遞的資料 (可夾帶常用且不重要的資料)
            var payload = new Dictionary<string, object>
            {
                //依需求存東西
                //加密後的明碼，敏感資訊不要放在這
                { "UserId", UserId },
                //{ "Exp", DateTime.Now.AddMinutes(30).ToString() } // JwtToken 時效設定 30 分
                { "Exp", DateTime.Now.AddMinutes(1440).ToString() } // JwtToken 時效設定 1440 分
            };

            // 產生 JwtToken
            var token = JWT.Encode(payload, Encoding.UTF8.GetBytes(secretKey), JwsAlgorithm.HS512);
            return token;
        }

        /// <summary>
        /// 生成只刷新效期的 JwtToken
        /// </summary>
        /// <returns>JwtToken</returns>
        public string ExpRefreshToken(Dictionary<string, object> tokenData)
        {
            //int expTime = 60 * 24;  //60min/h *24h/day
            //string secretKey = WebConfigurationManager.AppSettings["TokenKey"];
            // payload 從原本 token 傳遞的資料沿用，並刷新效期
            var payload = new Dictionary<string, object>
            {
                { "UserId", (int)tokenData["UserId"] },
                //{ "UserEmail", tokenData["UserEmail"].ToString() },
                //{ "UserName", tokenData["UserName"].ToString() },
                //{ "ThumbnailPath", tokenData["ThumbnailPath"].ToString() },
                //{ "Exp", DateTime.Now.AddMinutes(1440).ToString() } // JwtToken 時效刷新設定 30 分
                { "Exp", DateTime.Now.AddDays(1).ToString() } // JwtToken 時效刷新設定 1天
            };

            //產生刷新時效的 JwtToken
            var token = JWT.Encode(payload, Encoding.UTF8.GetBytes(secretKey), JwsAlgorithm.HS512);
            return token;
        }

        /// <summary>
        /// 生成無效 JwtToken
        /// </summary>
        /// <returns>JwtToken</returns>
        public string RevokeToken()
        {
            string secretKey = "RevokeToken"; // 故意用不同的 key 生成
            var payload = new Dictionary<string, object>
            {
                { "UserId", 0 },
                //{ "UserEmail", "None" },
                //{ "UserName", "None" },
                //{ "ThumbnailPath", "None" },
                { "Exp", DateTime.Now.AddDays(-1440).ToString() } // 使 JwtToken 過期 失效
            };

            // 產生失效的 JwtToken
            var token = JWT.Encode(payload, Encoding.UTF8.GetBytes(secretKey), JwsAlgorithm.HS512);
            return token;
        }



        /// <summary>
        /// 將 Token 解密取得夾帶的資料
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static Dictionary<string, object> GetPayload(string token)  //可以改成GetPayload比較好理解
        {
            return JWT.Decode<Dictionary<string, object>>(token, Encoding.UTF8.GetBytes(secretKey), JwsAlgorithm.HS512);
        }




        /// <summary>
        /// 生成只刷新效期的 JwtToken
        /// </summary>
        /// <returns>JwtToken</returns>
        public string ExpRefreshToken2(Dictionary<string, object> tokenData)
        {
            //string secretKey = WebConfigurationManager.AppSettings["TokenKey"];
            // payload 從原本 token 傳遞的資料沿用，並刷新效期
            var payload = new Dictionary<string, object>
            {
                { "UserId", (int)tokenData["UserId"] },
                //{ "UserEmail", tokenData["UserEmail"].ToString() },
                //{ "UserName", tokenData["UserName"].ToString() },
                //{ "ThumbnailPath", tokenData["ThumbnailPath"].ToString() },
                { "Exp", DateTime.Now.AddMinutes(-60).ToString() } // JwtToken 時效刷新設定 30 分
            };

            //產生刷新時效的 JwtToken
            var token = JWT.Encode(payload, Encoding.UTF8.GetBytes(secretKey), JwsAlgorithm.HS512);
            return token;
        }
    }
}