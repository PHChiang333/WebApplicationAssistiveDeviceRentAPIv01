using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using Newtonsoft.Json;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class Inquiry
    {

        //識別主鍵
        [Key]
        [Display(Name = "InquiryId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int InquiryId { get; set; }

        public virtual ICollection<InquiryProduct> InquiryProducts { get; set; }

        public virtual ICollection<Suggest> Suggests { get; set; }



        //
        [Display(Name = "詢問單編號InquiryCode")]
        public string InquiryCode { get; set; }


        //Foreign key 
        [Required]
        [Display(Name = "UserId")]
        public int UserId { get; set; }
        [JsonIgnore]
        [ForeignKey("UserId")]
        public virtual User GetUserId { get; set; }

        //
        [Display(Name = "是否已回覆建議單IsReplied")]
        public bool? IsReplied { get; set; }

        //
        [Display(Name = "GMFM等級GMFMLvCode")]
        public string GMFMLvCode { get; set; }

        //
        [Display(Name = "補充說明additionalInfo")]
        public string additionalInfo { get; set; }


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