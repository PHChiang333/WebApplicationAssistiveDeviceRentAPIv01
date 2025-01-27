using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using Newtonsoft.Json;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class Order
    {
        //識別主鍵
        [Key]
        [Display(Name = "OrderId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int OrderId { get; set; }


        //"訂單流水號: 日期(8)+流水號(4)  202501050001"
        [Display(Name = "訂單流水號OrderCode")]
        public string OrderCode { get; set; }


        ////Foreign key 
        //[Required]
        [Display(Name = "UserId")]
        public int UserId { get; set; }
        //[JsonIgnore]
        //[ForeignKey("UserId")]
        //public virtual User GetUserId { get; set; }


        //Foreign key 
        [Required]
        [Display(Name = "CartId")]
        public int CartId { get; set; }
        [JsonIgnore]
        [ForeignKey("CartId")]
        public virtual Cart GetCartId { get; set; }

        ////Foreign key 
        //[Required]
        [Display(Name = "ProductId")]
        public int ProductId { get; set; }
        //[JsonIgnore]
        //[ForeignKey("ProductId")]
        //public virtual Product GetProductId { get; set; }

        //產品名稱

        [Display(Name = "產品名稱ProductName")]
        public string ProductName { get; set; }


        //產品描述
        [Display(Name = "商品描述ProductDesc")]
        public string ProductDesc { get; set; }


        //租金

        [Display(Name = "租金Rent")]
        public decimal? Rent { get; set; }



        //押金

        [Display(Name = "押金Deposit")]
        public decimal? Deposit { get; set; }


        //商品圖片路徑
        [Display(Name = "商品圖片路徑ImgSrc")]
        public string ImgSrc { get; set; }



        //運送方式
        [Display(Name = "運送方式shipping")]
        public string shipping { get; set; }


        //運費
        [Display(Name = "運費fee")]
        public decimal? fee { get; set; }

        //
        [Display(Name = "商品數量Quantity")]
        public int? Quantity { get; set; }


        //
        [Display(Name = "總金額FinalAmount")]
        public decimal? FinalAmount { get; set; }


        //
        [Display(Name = "租賃時間(天)Period")]
        public int Period { get; set; }


        [Display(Name = "租賃日期(起始日)RentDate")]
        public DateTime? RentDate { get; set; }

        //歸還日期(結束日)

        [Display(Name = "歸還日期(結束日)returnDate")]
        public DateTime? ReturnDate { get; set; }

        //
        [Display(Name = "收件人RecipientName")]
        public string RecipientName { get; set; }

        //
        [Display(Name = "收件人電話RecipientPhone")]
        public string RecipientPhone { get; set; }


        //
        [Display(Name = "收件人EmailRecipientEmail")]
        public string RecipientEmail { get; set; }








        //
        [Display(Name = "收件人地址郵遞區號RecipientAddressZIP")]
        public string RecipientAddressZIP { get; set; }

        //
        [Display(Name = "收件人地址(縣市)RecipientAddressCity")]
        public string RecipientAddressCity { get; set; }


        //
        [Display(Name = "收件人地址(區)RecipientAddressDistinct")]
        public string RecipientAddressDistinct { get; set; }

        //
        [Display(Name = "收件人地址(其他)RecipientAddressDetail")]
        public string RecipientAddressDetail { get; set; }

        //
        [Display(Name = "付款方式PaymentBy")]
        public string PaymentBy { get; set; }


        //
        [Display(Name = "訂單狀態OrderStatus")]
        public string OrderStatus { get; set; }

        //
        [Display(Name = "物流狀態ShippingStatus")]
        public string ShippingStatus { get; set; }


        //
        [Display(Name = "備註note")]
        public string note { get; set; }

        //
        [Display(Name = "預計抵達日期EstimatedArrivalDate")]
        public string EstimatedArrivalDate { get; set; }

        //
        [Display(Name = "取貨驗證碼PickupVerificationCode")]
        public string PickupVerificationCode { get; set; }



        //------金流用屬性-------------------------

        ////LinePay
        [Display(Name = "LinePay交易Id TransactionId")]
        public string TransactionId { get; set; }


        //自動屬性

        [Display(Name = "CreateAt")]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:d}")]
        [DataType(DataType.DateTime)]
        public DateTime CreateAt { get; set; }

        [Display(Name = "UpdateAt")]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:d}")]
        [DataType(DataType.DateTime)]
        public DateTime UpdateAt { get; set; }


        [Display(Name = "IsDeleted")]
        public bool IsDeleted { get; set; }

        [Display(Name = "DeleteAt")]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:d}")]
        [DataType(DataType.DateTime)]
        public DateTime? DeleteAt { get; set; }











    }
}