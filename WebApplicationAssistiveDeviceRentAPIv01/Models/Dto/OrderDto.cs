using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models.Dto
{

    //取得全部訂單

    public class OrdersDto
    {

        public int orderId { get; set; }

        public string memberName { get; set; }
        public string orderStatus { get; set; }
        public string shippingStatus { get; set; }
        public string orderCode { get; set; }
        public DateTime createdDate { get; set; }
        public string createdStamp { get; set; }
        public string shipping { get; set; }
        public OrdersDetailsDto details { get; set; }
    }

    public class OrdersDetailsDto
    {
        public int quantity { get; set; }
        public string productName { get; set; }
        public string productDes { get; set; }
        public string productImgSrc { get; set; }
        public string productImgAlt { get; set; }
        public decimal rent { get; set; }
        public decimal deposit { get; set; }
        public decimal fee { get; set; }
        public decimal feeDeposit { get; set; }
        public decimal finalAmount { get; set; }
        public DateTime rentDate { get; set; }
        public string rentStamp { get; set; }
        public DateTime returnDate { get; set; }
        public string returnStamp { get; set; }

    }

    //取得訂單細節用

    public class OrderDetailDto
    {
        public string orderStatus { get; set; }
        public string shippingStatus { get; set; }
        public string orderCode { get; set; }
        public DateTime createdDate { get; set; }
        public string createdStamp { get; set; }

        public string note { get; set; }
        public string shipping { get; set; }

        public OrderDetailShippingInfoDto shippinginfo { get; set; }

        public OrderDetailDetailsDto details { get; set; }
    }

    public class OrderDetailShippingInfoDto
    {
        public string name { get; set; }
        public string phone { get; set; }
        public string email { get; set; }
        public string address { get; set; }
    }

    public class OrderDetailDetailsDto
    {
        public int quantity { get; set; }
        public string productName { get; set; }
        public string productDes { get; set; }
        public string productImgSrc { get; set; }
        public string productImgAlt { get; set; }
        public decimal rent { get; set; }
        public decimal deposit { get; set; }
        public decimal fee { get; set; }
        //public decimal feeDeposit { get; set; }
        public decimal finalAmount { get; set; }
        public int period { get; set; }
        public DateTime rentDate { get; set; }
        public string rentStamp { get; set; }
        public DateTime returnDate { get; set; }
        public string returnStamp { get; set; }

        public string payment { get; set; }
    }







    //建立訂單用


    //前端回傳的Request

    public class OrderRequestDto
    {
        public ORProduct product { get; set; }

        public string payment { get; set; }

        public ORShipping shipping { get; set; }

        public string confirmUrl { get; set; }   //測試LinePay用

    }

    public class ORProduct
    {
        public int id { get; set; }  //cartId, 抓入productId, 取得product資料存到order, 並更改cartId 為 IsTurnedOrder = true

        public string name { get; set; }
        public string imgSrc { get; set; }
        public string imgAlt { get; set; }
        public int quantity { get; set; }

        //public DateTime rentDate { get; set; }
        public DateTime rentStamp { get; set; }

        //public DateTime returnDate { get; set; }
        public DateTime returnStamp { get; set; }
        public int period { get; set; }
        public decimal rent { get; set; }

        public decimal deposit { get; set; }
        public decimal fee { get; set; }
        public decimal finalAmount { get; set; }
    }

    public class ORShipping
    {
        public string method { get; set; }

        public ORShippingData data { get; set; }
    }

    public class ORShippingData
    {
        //收件人資料
        public string userName { get; set; }
        public string phone { get; set; }
        public string email { get; set; }

        //店家資料
        //public string storeName { get; set; }
        //public string storePhone { get; set; }
        //public string storeTime { get; set; }
        //public string storeAddress { get; set; }

        //收件人地址
        public string addressZip { get; set; }
        public string addressCity { get; set; }
        public string addressDistrict { get; set; }
        public string addressDetail { get; set; }

    }


    //取得所有使用者訂單

    public class OrdersAdminDto
    {
        public int orderId { get; set; }

        public string memberName { get; set; }
        public string orderStatus { get; set; }
        public string shippingStatus { get; set; }
        public string orderCode { get; set; }
        public DateTime createdDate { get; set; }
        public string createdStamp { get; set; }
        public string shipping { get; set; }
        public int quantity { get; set; }
        public decimal finalAmount { get; set; }
        public DateTime rentDate { get; set; }
        public string rentStamp { get; set; }
        public DateTime returnDate { get; set; }
        public string returnStamp { get; set; }
    }


    //編輯訂單狀態

    public class OrderUpdateAdminDto
    {
        public int orderId { get; set; }  //辨識
        public string orderStatus { get; set; }
        public string shippingStatus { get; set; }
        //public string orderCode { get; set; }   //取消
    }




    // 編輯訂單訊息(管理者後台)

    public class OrderDetailUpdateAdminDto
    {
        public int memberId { get; set; }
        public string orderCode { get; set; }
        public string orderStatus { get; set; }
        public string shipping { get; set; }
        public string shippingStatus { get; set; }

        public OrderDetailUpdateAdminShippingInfoDto shippingInfo { get; set; }

        public OrderDetailUpdateAdminDetailDto details { get; set; }

    }

    public class OrderDetailUpdateAdminShippingInfoDto
    {
        public string name { get; set; }
        public string phone { get; set; }
        public string email { get; set; }
        public string addressZip { get; set; }
        public string addressCity { get; set; }
        public string addressDistrict { get; set; }
        public string addressDetail { get; set; }
    }

    public class OrderDetailUpdateAdminDetailDto
    {
        public int quantity { get; set; }
        public string productName { get; set; }
        public decimal rent { get; set; }
        public decimal deposit { get; set; }
        public decimal fee { get; set; }
        public decimal finalAmount { get; set; }
        public DateTime rentStamp { get; set; }
        public DateTime returnStamp { get; set; }
        public string payment { get; set; }
    }
}