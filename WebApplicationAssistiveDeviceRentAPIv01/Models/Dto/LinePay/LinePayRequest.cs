using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models.Dto.LinePay
{
    public class LinePayRequest
    {
    }

    // 送出請求格式以及必要屬性
    public class LinePayRequestDto
    {
        public int amount { get; set; }
        public string currency { get; } = "TWD";
        public string orderId { get; set; }
        public List<PackageDto> packages { get; set; }
        public RedirectUrlsDto redirectUrls { get; set; }
    }

    public class PackageDto
    {
        public string id { get; set; }
        public int amount { get; set; }
        public List<ProductDto> products { get; set; }

        public string name { get; set; }
    }

    public class RedirectUrlsDto
    {
        public string confirmUrl { get; set; }
        public string cancelUrl { get; set; }
    }

    public class ProductDto
    {
        public string name { get; set; }
        public int quantity { get; set; }
        public int price { get; set; }
    }

    // 接收LinePay的回應，建議獲取transactionId才方便完成Confirm API的操作
    public class LinePayResponseDto
    {
        public string returnCode { get; set; }
        public string returnMessage { get; set; }
        public LinePayResponseInfoDto info { get; set; }
    }

    public class LinePayResponseInfoDto
    {
        public long transactionId { get; set; }
        public PaymentUrlDto paymentUrl { get; set; }
    }

    public class PaymentUrlDto
    {
        public string web { get; set; }
        public string app { get; set; }
    }




}