using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using System.Text.Json.Serialization;
using System.Data.Entity;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class Product
    {
        //識別主鍵
        [Key]
        [Display(Name = "ProductId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ProductId { get; set; }

        //Foreign key 
        public virtual ICollection<ProductImg> ProductImgs { get; set; }
        public virtual ICollection<ProductFeature> ProductFeatures { get; set; }
        public virtual ICollection<ProductInfo> ProductInfos { get; set; }

        public virtual ICollection<ProductGMFMLv> ProductGMFMLvs { get; set; }

        public virtual ICollection<ProductBodyPart> ProductBodyParts { get; set; }

        //public virtual ICollection<Cart> Carts { get; set; }
        //public virtual ICollection<Order> Orders { get; set; }
        //public virtual ICollection<InquiryProduct> InquiryProducts { get; set; }
        //public virtual ICollection<SuggestProduct> SuggestProducts { get; set; }


        //產品名稱
        [Required]
        [Display(Name = "產品名稱ProductName")]
        public string ProductName { get; set; }



        //Foreign key 
        [Required]
        [Display(Name = "ProductTypeId")]
        public int ProductTypeId { get; set; }
        [JsonIgnore]
        [ForeignKey("ProductTypeId")]
        public virtual ProductType GetProductTypeId { get; set; }


        //租金
        [Required]
        [Display(Name = "租金Rent")]
        public decimal? Rent { get; set; }

        //押金
        [Required]
        [Display(Name = "押金Deposit")]
        public decimal? Deposit { get; set; }


        //運費
        [Required]
        [Display(Name = "運費Fee")]
        public decimal? Fee { get; set; }



        [Display(Name = "商品描述ProductDesc")]
        public string ProductDesc { get; set; }

        [Display(Name = "商品使用說明ProductManual")]
        public string ProductManual { get; set; }


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