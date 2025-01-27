using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models.Dto
{

    //取得使用者特定建議單(帶單號)
    public class SuggestDto
    {
        public int suggestId { get; set; }

        public string suggestCode { get; set; }
        public DateTime createdDate { get; set; }
        public string createdStamp { get; set; }
        public string additionalInfo { get; set; }
        public string level { get; set; }

        public List<SuggestProductDto> products { get; set; }

    }

    public class SuggestProductDto
    {
        public int id { get; set; }  //productId
        public string name { get; set; }
        public string description { get; set; }

        public decimal rent { get; set; }

        public string imgSrc { get; set; }
        public string imgAlt { get; set; }

        public string[] features { get; set; }

        public string reasons { get; set; }

    }


    //取得特定建議單(by詢問單)(未送出)（店家後台）
    public class SuggestNotSubmittedDto
    {
        public int suggestId { get; set; }
        public string suggestCode { get; set; }
        public string level { get; set; }
        public string additionalInfo { get; set; }
        public List<SuggestNotSubmittedProductDto> products { get; set; }

    }

    public class SuggestNotSubmittedProductDto
    {
        public int suggestProductId { get; set; }  //suggestProductId
        public int productId { get; set; }  //productId
        public string name { get; set; }
        public string description { get; set; }

        public decimal rent { get; set; }

        public string imgSrc { get; set; }
        public string imgAlt { get; set; }

        public string[] features { get; set; }

        public string reasons { get; set; }

    }

    //添加建議單商品

    public class SuggestAddProductRequestdDto
    {
        public int suggestId { get; set; }
        public int productId { get; set; }

    }

    public class SuggestAddProductDto
    {
        public int suggestProductId { get; set; }
        public SuggestAddProductProductDto product { get; set; }

    }

    public class SuggestAddProductProductDto
    {
        public int id { get; set; }  //productId
        public string name { get; set; }
        public string description { get; set; }

        public decimal rent { get; set; }

        public string imgSrc { get; set; }
        public string imgAlt { get; set; }

        public string[] features { get; set; }

        public string reasons { get; set; }

    }

    //編輯建議單商品(info)

    public class SuggestUpdateProductRequestdDto
    {

        public int suggestProductId { get; set; }
        public int productId { get; set; }

        public string reasons { get; set; }

    }

    //刪除建議單商品

    public class SuggestDeleteProductRequestdDto
    {

        public int suggestProductId { get; set; }

    }


    //編輯建議單(上方資訊)

    public class SuggestUpdateInfoRequestDto
    {

        public int suggestId { get; set; }
        public string level { get; set; }
        public string additionalInfo { get; set; }
        public bool isSubmitted { get; set; }

    }



}