using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using WebApplicationAssistiveDeviceRentAPIv01.Class;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models.Dto
{
    //店家撈全部需求單
    public class InquiriesDto
    {
        public int inquiryId { get; set; }

        public string inquiryCode { get; set; }

        public DateTime createdDate { get; set; }
        public string createdStamp { get; set; }
        public bool isReplied { get; set; }

        public List<InquiriesProductsDto> images { get; set; }

        public int suggetsId { get; set; }

        public string suggetsCode { get; set; }



    }
    public class InquiriesProductsDto
    {
        public string src { get; set; }
        public string alt { get; set; }
    }



    //撈特定需求單
    public class InquiryDto
    {
        public int inquiryId { get; set; }

        public string inquiryCode { get; set; }

        public DateTime createdDate { get; set; }
        public string createdStamp { get; set; }

        public string level { get; set; }

        public string additionalInfo { get; set; }
        public List<InquiryProductDto> products { get; set; }

    }

    public class InquiryProductDto
    {
        public int id { get; set; }  //productId
        public string name { get; set; }
        public string description { get; set; }

        public decimal rent { get; set; }

        public string imgSrc { get; set; }
        public string imgAlt { get; set; }

        public string[] features { get; set; }
    }


        //添加詢問單

        public class InquiryAddRequestDto
    {
        public List<int> productIds { get; set; }

        public string level { get; set; }

        public string additionalInfo { get; set; }
    }

    //取得未完成詢問單商品資料(使用者)

    public class InquiryUnfinishedRequestDto
    {
        public List<int> productIds { get; set; }
    }

    public class InquiryUnfinishedProductsDto
    {
        public int id { get; set; }  //productId
        public string name { get; set; }
        public string description { get; set; }

        public decimal rent { get; set; }

        public string imgSrc { get; set; }
        public string imgAlt { get; set; }

        public string[] features { get; set; }


    }


    //取得全部詢問單/建議單(店家後台)

    public class InquiryByAdminDto
    {
        public int inquiryId { get; set; }

        public string inquiryCode { get; set; }

        public bool isReplied { get; set; }

        public DateTime createdDate { get; set; }
        public string createdStamp { get; set; }

        public int suggestId { get; set; }

        public string suggestCode { get; set; }

        public InquiryByAdminMemberDto member { get; set; }

    }

    public class InquiryByAdminMemberDto
    {
        public string memberName { get; set; }

        public string email { get; set; }

        public string lineId { get; set; }

    }


}