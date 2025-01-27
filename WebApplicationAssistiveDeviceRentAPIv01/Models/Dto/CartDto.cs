using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models.Dto
{
    public class CartDto
    {
        public int cartId { get; set; }

        public string name { get; set; }

        public string description { get; set; }
        public int quantity { get; set; }
        public decimal rent { get; set; }
        public decimal deposit { get; set; }

        public decimal fee { get; set; }
        public decimal amount { get; set; }
        public int period { get; set; }



        public DateTime rentDate { get; set; }
        public string rentStamp { get; set; }

        public DateTime returnDate { get; set; }

        public string returnStamp { get; set; }
        public string imgSrc { get; set; }

        public string imgAlt { get; set; }

    }

    public class CartAddRequestDto
    {
        public int id { get; set; }  //productId
    }


    public class CartAddDto
    {
        public int userId { get; set; }
    }

    public class CartUpdateRequestDto
    {
        public int cartId { get; set; }  //cartId
        public int quantity { get; set; }  //
        public int period { get; set; }  //
        public string rentStamp { get; set; }  //
    }


    public class CartUpdateQuantityDto
    {
        public int CartId { get; set; }
        public int Quantity { get; set; }
    }

    public class CartUpdatePeriodDto
    {
        public int CartId { get; set; }
        public int Period { get; set; }
    }

    public class CartUpdateRentStampDto
    {
        public int CartId { get; set; }
        public string RentStamp { get; set; }
    }


    public class CartDeleteRequestDto
    {
        public int id { get; set; }  //CartId

        public int productId { get; set; }


    }



    

}