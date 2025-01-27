using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Class
{
    public class HmacSignature
    {
        public static string GenerateHmacSignature(string channelSecret, string message)
        {
            // 轉換為bytes array
            byte[] keyBytes = Encoding.UTF8.GetBytes(channelSecret);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            // 透過HMAC-256算法計算channelSecret與message並回傳
            using (var hmac256 = new HMACSHA256(keyBytes))
            {
                byte[] hashBytes = hmac256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }




    }
}