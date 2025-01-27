using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.IO;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class User
    {

        [Key]
        [Display(Name = "UserId")]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int UserId { get; set; }


        // Foreign Key 
        public virtual ICollection<UserInfo> UserInfos { get; set; }

        //public virtual ICollection<Cart> Carts { get; set; }
        //public virtual ICollection<Order> Orders { get; set; }
        //public virtual ICollection<Inquiry> Inquirys { get; set; }

        // Foreign Key 




        [Display(Name = "UserEmail")]
        [Required(ErrorMessage = "Email is required.")]
        [StringLength(254, ErrorMessage = "Email cannot exceed 254 characters.")]
        [RegularExpression(@"^(?=.{1,64}@.{1,253}$)(?=.{1,254}$)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ErrorMessage = "Invalid email format.")]
        //信箱：RFC 5322 標準
        // - edge case
        // - @ 前方不得超過 64 個字元
        // - 電子信箱長度不得超過 254 個字元
        public string UserEmail { get; set; }


        [MaxLength(100)]
        [Display(Name ="UserName")]
        public string UserName { get; set; }



        [Required(ErrorMessage = "{0} is required.")]
        [StringLength(64, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 64 characters.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?""{}|<>]).{8,64}$", ErrorMessage = "Password must include at least one uppercase letter, one lowercase letter, one digit, and one special character.")]
        //密碼：NIST SP 800-63B 標準
        //- edge case
        //- 密碼長度不得超過 64 個字元
        //- 密碼長度必須至少 8 個字符，並且包含 1 個大寫英文字母、1 個小寫英文字母、1 個數字和 1 個標點符號
        [Display(Name = "UserPassword")]
        public string UserPassword { get; set; }

        //[Display(Name = "UserPhone")]
        //public string UserPhone { get; set; }


        [Display(Name ="ThumbnailPath")]
        public string ThumbnailPath { get; set; }

        [Display(Name = "JWTtoken")]
        public string JWTtoken { get; set; }


        [Display(Name = "IsAdmin")]
        public bool IsAdmin { get; set; }


        [Display(Name = "LineId")]
        public string LineId { get; set; }


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