using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using WebApplicationAssistiveDeviceRentAPIv01.Class;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models.Dto
{
    public class AuthDto
    {
    }

    //public class responseLogin
    //{
    //    public string StatusCode { get; set; }
    //    public string Status { get; set; }
    //    public string Msg { get; set; }
    //    public UserDto Data { get; set; }
    //}

    //public class authRequest
    //{
    //    public string JWTtoken { get; set; }
    //}

    public class requestRegister
    {
        public string Name { get; set; }
        //public string Phone { get; set; }
        public string Email { get; set; }  //unique
        public string Password { get; set; }
    }


    public class requestLogin
    {
        public string Email { get; set; }  //unique
        public string Password { get; set; }
    }

}