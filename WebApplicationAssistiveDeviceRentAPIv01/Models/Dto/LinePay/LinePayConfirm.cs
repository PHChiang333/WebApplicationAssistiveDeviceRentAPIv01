using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models.Dto.LinePay
{
    public class LinePayConfirm
    {
    }


    // 送出請求格式以及必要屬性
    public class ConfirmRequestDto
    {
        public long transactionId { get; set; }
        public int amount { get; set; }
        public string currency { get; } = "TWD";
    }

    // 接收LinePay的回應
    public class PaymentConfirmResponseDto
    {
        public string returnCode { get; set; }
        public string returnMessage { get; set; }
    }



    public class ConfirmRequestFromFrontendDto
    {
        public long transactionId { get; set; }
        //public int finalAmount { get; set; }

        public int orderId { get; set; }
    }



}