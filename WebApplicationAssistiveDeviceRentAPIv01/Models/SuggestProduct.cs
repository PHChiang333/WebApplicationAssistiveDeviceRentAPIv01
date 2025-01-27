using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using Newtonsoft.Json;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class SuggestProduct
    {

        //識別主鍵
        [Key]
        [Display(Name = "SuggestProductId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int SuggestProductId { get; set; }

        //Foreign key 
        [Required]
        [Display(Name = "SuggestId")]
        public int SuggestId { get; set; }
        [JsonIgnore]
        [ForeignKey("SuggestId")]
        public virtual Suggest GetSuggestId { get; set; }


        //Foreign key 
        [Required]
        [Display(Name = "ProductId")]
        public int ProductId { get; set; }
        [JsonIgnore]
        [ForeignKey("ProductId")]
        public virtual Product GetProductId { get; set; }



        //
        [Display(Name = "建議事項Reasons")]
        public string Reasons { get; set; }





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