﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using WebApplicationAssistiveDeviceRentAPIv01.Models;

namespace WebApplicationAssistiveDeviceRentAPIv01.Controllers
{
    public class ValuesController : ApiController
    {
        
        private DBModel db = new DBModel();


        // GET api/test
        [HttpGet]
        [Route("api/test")]
        public IHttpActionResult test()
        {
            return Ok(new {msg="OK"});
        }



        // GET api/values
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        public string Get(int id)
        {
            return "value";
        }

        // POST api/values
        public void Post([FromBody] string value)
        {
        }

        // PUT api/values/5
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        public void Delete(int id)
        {
        }
    }
}
