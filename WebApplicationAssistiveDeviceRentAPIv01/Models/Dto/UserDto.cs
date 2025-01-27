using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Class
{
    public class UserDto
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string Nickname { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public string Thumbnail { get; set; }
        public string JWTToken { get; set; }

    }


    public class UserProfileDto
    {
        public string name { get; set; }
        public string gender { get; set; }
        public DateTime dobDate { get; set; }
        public string dobStamp { get; set; }
        public string email { get; set; }
        public string phone { get; set; }
        public string contactTime { get; set; }
        public string addressZip { get; set; }
        public string addressCity { get; set; }
        public string addressDistrict { get; set; }
        public string addressDetail { get; set; }

    }

    public class UserProfileUpdateRequestDto
    {
        public string name { get; set; }
        public string gender { get; set; }
        //public DateTime dobDate { get; set; }
        public DateTime dobStamp { get; set; }
        //public string email { get; set; }
        public string phone { get; set; }
        public string contactTime { get; set; }
        public string addressZip { get; set; }
        public string addressCity { get; set; }
        public string addressDistrict { get; set; }
        public string addressDetail { get; set; }

    }


}