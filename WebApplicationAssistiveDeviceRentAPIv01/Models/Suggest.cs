using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using Newtonsoft.Json;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class Suggest
    {
        //識別主鍵
        [Key]
        [Display(Name = "SuggestId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int SuggestId { get; set; }

        public virtual ICollection<SuggestProduct> SuggestProducts { get; set; }




        //
        [Display(Name = "建議單編號SuggestCode")]
        public string SuggestCode { get; set; }


        //Foreign key 
        [Required]
        [Display(Name = "InquiryId")]
        public int InquiryId { get; set; }
        [JsonIgnore]
        [ForeignKey("InquiryId")]
        public virtual Inquiry GetInquiryId { get; set; }


        //
        [Display(Name = "GMFM等級GMFMLvCode")]
        public string GMFMLvCode { get; set; }

        //
        [Display(Name = "補充說明additionalInfo")]
        public string additionalInfo { get; set; }


        //
        [Display(Name = "是否已送出IsSubmitted")]
        public bool? IsSubmitted { get; set; }

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