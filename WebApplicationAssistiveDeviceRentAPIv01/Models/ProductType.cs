using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class ProductType
    {
        //識別主鍵
        [Key]
        [Display(Name = "ProductTypeId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ProductTypeId { get; set; }

        //Foreign key 
        public virtual ICollection<Product> Products { get; set; }

        //商品分類名稱
        [Required]
        [Display(Name = "商品分類名稱ProductType")]
        public string ProductTypeName { get; set; }






        //自動屬性

        [Display(Name = "CreateAt")]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:d}")]
        [DataType(DataType.DateTime)]
        public DateTime? CreateAt { get; set; }

        [Display(Name = "UpdateAt")]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:d}")]
        [DataType(DataType.DateTime)]
        public DateTime? UpdateAt { get; set; }


        [Display(Name = "IsDeleted")]
        public bool? IsDeleted { get; set; }

        [Display(Name = "DeleteAt")]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:d}")]
        [DataType(DataType.DateTime)]
        public DateTime? DeleteAt { get; set; }




    }
}