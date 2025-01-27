using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class UserInfo
    {

        //識別主鍵
        [Key]
        [Display(Name ="UserInfoId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int UserInfoId {  get; set; }

        //Foreign key 

        [Display(Name = "UserId")]
        public int UserId { get; set; } //表示外鍵，用來參考 User 類別中的主鍵

        [JsonIgnore]
        [ForeignKey("UserId")] //標示 MyOrg 是一個外鍵導航屬性
        public virtual User GetUserId { get; set; } //導航屬性，用來表示與 User 類別的關聯

        //Foreign key 


        [Display(Name = "Nickname")]
        public string Nickname { get; set; }


        [Display(Name = "Gender")]
        public string Gender { get; set; }

        [Display(Name = "Birth")]
        public DateTime? Birth { get; set; }

        [Display(Name = "UserPhone")]
        public string UserPhone { get; set; }


        //可以聯繫的時間段
        [Display(Name = "AllowedContactPeriod")]
        public string AllowedContactPeriod { get; set; }


        //地址
        [Display(Name = "AddressZIP")] 
        public string AddressZIP { get; set; }

        [Display(Name = "AddressCity")] 
        public string AddressCity { get; set; }

        [Display(Name = "AddressDistinct")] 
        public string AddressDistinct { get; set; }

        [Display(Name = "AddressDetail")] 
        public string AddressDetail { get; set; }


        //收入等級:低收or中低收
        [Display(Name = "低收或中低收IncomeLv")]
        public string IncomeLv { get; set; }

        //是否身障
        [Display(Name = "是否身障IsDisability")]
        public string IsDisability { get; set; }










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