using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Class
{
    public class Function
    {

        /// <summary>
        /// 產生4碼英文大小寫及數字混雜的隨機碼
        /// </summary>
        /// <returns></returns>
        public static string GenerateRandomCode()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            char[] result = new char[4];

            for (int i = 0; i < 4; i++)
            {
                result[i] = chars[random.Next(chars.Length)];
            }

            return new string(result);
        }

        /// <summary>
        /// 需求單 InquiryCode生成方法  AA(2碼英文)+001(3碼流水號)
        /// </summary>
        /// <param name="currentOrder"></param>
        /// <returns></returns>
        public static string GenerateNextOrderNumber(string currentOrder)
        {
            // 分離字母與數字部分
            string prefix = currentOrder.Substring(0, 2); // 前兩個字母
            int number = int.Parse(currentOrder.Substring(2)); // 後三個數字

            // 處理數字部分
            number++;
            if (number > 999)
            {
                number = 1; // 數字重置為 001
                prefix = IncrementPrefix(prefix); // 字母部分進位
            }

            // 格式化回訂單號碼
            return $"{prefix}{number:D3}";
        }

        /// <summary>
        /// 判斷2碼英文代碼是否進位
        /// 用於: 需求單 InquiryCode生成方法  AA(2碼英文)+0001(4碼流水號)
        /// </summary>
        /// <param name="prefix"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static string IncrementPrefix(string prefix)
        {
            char firstChar = prefix[0];
            char secondChar = prefix[1];

            // 處理第二個字母的進位
            if (secondChar == 'Z')
            {
                secondChar = 'A';
                firstChar++; // 第一個字母進位
            }
            else
            {
                secondChar++;
            }

            // 處理第一個字母溢出 (超過 'Z')
            if (firstChar > 'Z')
            {
                throw new InvalidOperationException("Prefix overflow, no more increments possible.");
            }

            return $"{firstChar}{secondChar}";
        }





    }


}