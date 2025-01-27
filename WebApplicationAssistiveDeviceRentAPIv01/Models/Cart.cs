using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using Newtonsoft.Json;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class Cart
    {
        //識別主鍵
        [Key]
        [Display(Name = "CartId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int CartId { get; set; }


        //Foreign key 
        //public virtual ICollection<Order> Orders { get; set; }







        //Foreign key 
        [Required]
        [Display(Name = "UserId")]
        public int UserId { get; set; }
        [JsonIgnore]
        [ForeignKey("UserId")]
        public virtual User GetUserId { get; set; }


        //Foreign key 
        [Required]
        [Display(Name = "ProductId")]
        public int ProductId { get; set; }
        [JsonIgnore]
        [ForeignKey("ProductId")]
        public virtual Product GetProductId { get; set; }



        ////產品名稱
        
        //[Display(Name = "產品名稱ProductName")]
        //public string ProductName { get; set; }


        ////產品描述
        //[Display(Name = "商品描述ProductDesc")]
        //public string ProductDesc { get; set; }


        ////租金
        
        //[Display(Name = "租金Rent")]
        //public decimal? Rent { get; set; }



        ////押金
        
        //[Display(Name = "押金Deposit")]
        //public decimal? Deposit { get; set; }


        ////商品圖片路徑
        //[Display(Name = "商品圖片路徑ImgSrc")]
        //public string ImgSrc { get; set; }


        //商品數量
        
        [Display(Name = "商品數量Quantity")]
        public int? Quantity { get; set; }

        //總金額
        
        [Display(Name = "總金額")]
        public decimal? Amount { get; set; }

        //租賃時間(天)
        
        [Display(Name = "租賃時間(天)Period")]
        public int? Period { get; set; }

        //租賃日期(起始日)
        
        [Display(Name = "租賃日期(起始日)RentDate")]
        public DateTime? RentDate  { get; set; }

        //歸還日期(結束日)
        
        [Display(Name = "歸還日期(結束日)returnDate")]
        public DateTime? ReturnDate { get; set; }

        //使否轉為訂單
        
        [Display(Name = "是否轉為訂單IsTurnedOrder")]
        public bool? IsTurnedOrder { get; set; }




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