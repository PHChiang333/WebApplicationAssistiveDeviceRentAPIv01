using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using Newtonsoft.Json;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class ProductImg
    {
        //識別主鍵
        [Key]
        [Display(Name = "ProductImgId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ProductImgId { get; set; }

        //Foreign key 
        [Required]
        [Display(Name = "ProductId")]
        public int ProductId { get; set; }
        [JsonIgnore]
        [ForeignKey("ProductId")]
        public virtual Product GetProductId { get; set; }

        [Required]
        [Display(Name = "商品圖片位址ProductInfoKey")]
        public string ProductImgPath { get; set; }



        [Display(Name = "商品圖片名稱")]
        public string ProductImgName { get; set; }



        [Display(Name = "是否預覽圖IsPreview")]
        public bool IsPreview { get; set; }




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