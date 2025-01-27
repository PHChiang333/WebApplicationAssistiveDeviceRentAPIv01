using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationAssistiveDeviceRentAPIv01.Class
{

    public class ProductsDto
    {
        public int id { get; set; }
        public string type { get; set; }
        public string name { get; set; }
        public string level { get; set; }
        public decimal rent { get; set; }

        public string imgSrc { get; set; }
        public string imgAlt { get; set; }

        public string[] features { get; set; }

        public string description { get; set; }
    }








    //商品細節
    public class ProductDetailWrapDto
    {
        public ProductDetailDto product { get; set; }

        public comparisonDto comparison { get; set; }

        public recommendedDto recommended { get; set; }

        //public int id { get; set; }
        //public string type { get; set; }
        //public string name { get; set; }
        //public string level { get; set; }
        //public double rent { get; set; }
        //public double deposit  { get; set; }
        //public double fee { get; set; }
        //public string description { get; set; }
        //public Dictionary<string, string> info { get; set; }
        //public string[] features { get; set; }
        //public ImageDto image { get; set; }

        //public string manual { get; set; }


    }


    public class ProductDetailDto
    {
        public int id { get; set; }
        public string type { get; set; }
        public string name { get; set; }
        public string level { get; set; }
        public decimal rent { get; set; }
        public decimal deposit { get; set; }
        public decimal fee { get; set; }
        public string description { get; set; }
        public Dictionary<string, string> info { get; set; }
        public string[] features { get; set; }
        public ImageDto image { get; set; }


        public string manual { get; set; }
    }





    public class ImageDto
    {
        public string preview { get; set; }
        public string previewAlt { get; set; }

        public string[] list { get; set; }

        public string[] listAlt { get; set; }
    }


    public class comparisonDto
    {

        public int productId { get; set; }
        public string imgSrc { get; set; }
        public string name { get; set; }
        public decimal rent { get; set; }
        public string material { get; set; }
        public string[] features { get; set; }

    }

    public class recommendedDto
    {
        public int productId { get; set; }
        public string imgSrc { get; set; }

        public string imgAlt { get; set; }
        public string name { get; set; }
        public decimal rent { get; set; }

        public string[] features { get; set; }

        public string description { get; set; }
    }

    public class UserIdTokenProfileDto
    {
        public string iss { get; set; }
        public string sub { get; set; }
        public string aud { get; set; }
        public int exp { get; set; }
        public int auth_time { get; set; }
        public int iat { get; set; }
        public string nonce { get; set; }
        public string[] amr { get; set; }
        public string name { get; set; }
        public string picture { get; set; }
        public string email { get; set; }
    }






}