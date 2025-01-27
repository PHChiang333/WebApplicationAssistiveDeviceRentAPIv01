using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using Newtonsoft.Json;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class InquiryProduct
    {

        //識別主鍵
        [Key]
        [Display(Name = "InquiryProductId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int InquiryProductId { get; set; }

        //Foreign key 
        [Required]
        [Display(Name = "InquiryId")]
        public int InquiryId { get; set; }
        [JsonIgnore]
        [ForeignKey("InquiryId")]
        public virtual Inquiry GetInquiryId { get; set; }


        //Foreign key 
        [Required]
        [Display(Name = "ProductId")]
        public int ProductId { get; set; }
        [JsonIgnore]
        [ForeignKey("ProductId")]
        public virtual Product GetProductId { get; set; }

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