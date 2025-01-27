using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class EnumList
    {
        public enum GenderType //預設是0.1.2開始....
        {
            男 = 0,
            女 = 1,
            其他 = 2
        }

        public enum StatusCode
        {
            Success = 200, // 成功
            BadRequest = 400, // 錯誤的請求
            Unauthorized = 401, // 未授權
            Forbidden = 403, // 禁止訪問
            NotFound = 404, // 資源不存在
            InternalServerError = 500, // 伺服器錯誤
            ServiceUnavailable = 503 // 服務不可用
        }


        public enum GMFMLv
        {
            lv1=1, // 具平地跑跳能力
            lv2 =2, // 在平地無法跑跳，但可放手行走
            lv3 =3, // 行走需扶持穩定物
            lv4 =4, // 無法行走，但能在無投靠支撐下維持坐姿
            lv5 = 5, // 無頭靠支撐下難以維持坐姿
            empty = -1   //空值

        }

        public enum Type
        {
            empty = -1   //空值
        }



        //public enum BodyPart
        //{
        //    headAndNeck=1, //頭部與頸部
        //    shoulder=2,  //肩部
        //    arm=3, //手臂
        //    wrist=4, //手腕
        //    spine=5,  //脊椎
        //    waist=6, //腰部
        //    hip =7, //髖部
        //    knee=8, //膝蓋
        //    ankle=9 //腳踝

        //}


        public enum payment
        {
            Cash = 0,
            LinePay = 1,
            Creditcard =2
        }

        public enum shipping
        {
            strore= 0,
            delivery = 1,
        }


    }


}