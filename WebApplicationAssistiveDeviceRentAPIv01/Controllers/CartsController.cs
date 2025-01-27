using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Web.Http;
using System.Web.Http.Description;
using WebApplicationAssistiveDeviceRentAPIv01.Class;
using WebApplicationAssistiveDeviceRentAPIv01.Models;
using WebApplicationAssistiveDeviceRentAPIv01.Models.Dto;
using WebApplicationAssistiveDeviceRentAPIv01.Security;

namespace WebApplicationAssistiveDeviceRentAPIv01.Controllers
{
    public class CartsController : ApiController
    {
        private DBModel db = new DBModel();



        [HttpGet]
        [JwtAuthFilter]
        [Route("api/v1/carts")]
        public IHttpActionResult Carts()
        {
            //int userId = Id;
            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            var queryCarts = db.Carts.Where(c => c.IsDeleted == false && c.IsTurnedOrder == false);

            try
            {
                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (queryCarts.Any(c => c.UserId == userId))
                {
                    var carts = queryCarts.Where(c => c.UserId == userId).ToList().Select(c => new CartDto
                    {

                        cartId = c.CartId,
                        name = c.GetProductId.ProductName ?? "",
                        description = c.GetProductId.ProductDesc ?? "",
                        quantity = c.Quantity ?? -99999,
                        rent = c.GetProductId.Rent ?? -99999,
                        deposit = c.GetProductId.Deposit ?? -99999,
                        fee = c.GetProductId.Fee ?? -99999,
                        //amount = c.Amount ?? -99999,
                        amount = (c.GetProductId.Rent ?? -1) + (c.GetProductId.Deposit ?? -2),
                        period = c.Period ?? -99999,
                        rentDate = (c.RentDate ?? DateTime.MinValue),
                        //rentStamp = (c.RentDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                        rentStamp = c.RentDate == null ? "" : (c.RentDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                        returnDate = (c.ReturnDate ?? DateTime.MinValue),
                        //returnStamp = (c.ReturnDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                        returnStamp = c.ReturnDate == null ? "" : (c.ReturnDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                        imgSrc = (ServerPath.Domain) + c.GetProductId.ProductImgs.Where(pi => pi.IsDeleted == false && pi.IsPreview == true).FirstOrDefault()?.ProductImgPath ?? "",
                        imgAlt = c.GetProductId.ProductName ?? ""
                    }).ToList() ?? new List<CartDto>();

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "成功取得購物車清單",
                        data = carts
                    };



                    return Ok(result);
                }
                else
                {
                    //var result = new
                    //{
                    //    statusCode = 404,
                    //    status = false,
                    //    message = "資源未找到",
                    //};
                    //return Ok(result);

                    //改成回空陣列

                    var carts = queryCarts.Where(c => c.UserId == userId).ToList().Select(c => new CartDto
                    {
                    }).ToList() ?? new List<CartDto>();

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "成功取得購物車清單(無購物車)",
                        data = carts
                    };

                    return Ok(result);
                }

            }
            catch (Exception ex)
            {

                var result = new
                {
                    statusCode = 500,
                    status = false,
                    message = "Server error",
                };
                return Ok(result);

            }
        }

        [HttpPost]
        [JwtAuthFilter]
        [Route("api/v1/carts")]
        public IHttpActionResult CartAdd([FromBody] CartAddRequestDto request)
        {

            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "新增購物車失敗"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {

                //先確認product存在
                if (db.Products.Where(p => p.IsDeleted == false).Any(p => p.ProductId == request.id))
                {

                    int userId = Convert.ToInt32(userToken["UserId"].ToString());

                    Cart cartAdd = new Cart();

                    cartAdd.UserId = userId;
                    cartAdd.ProductId = request.id;
                    cartAdd.Quantity = 1;
                    cartAdd.Period = 30;
                    //cartAdd.RentDate = DateTime.Now;  //預設值用當日
                    cartAdd.RentDate = null;  //預設值用當日
                    //cartAdd.ReturnDate = DateTime.Now; //預設值用當日
                    cartAdd.ReturnDate = null; //預設值用當日
                    cartAdd.IsTurnedOrder = false;

                    cartAdd.CreateAt = DateTime.Now;
                    cartAdd.UpdateAt = DateTime.Now;
                    cartAdd.IsDeleted = false;
                    cartAdd.DeleteAt = null;

                    db.Carts.Add(cartAdd);
                    db.SaveChanges();


                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "成功新增購物車",
                    };
                    return Ok(result);

                }
                else
                {
                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "商品不存在",
                    };
                    return Ok(result);
                }
            }
            catch (Exception ex)
            {

                var result = new
                {
                    statusCode = 500,
                    status = false,
                    message = "Server error",
                };
                return Ok(result);

            }
        }

        [HttpPut]
        [JwtAuthFilter]
        [Route("api/v1/carts")]
        public IHttpActionResult CartUpdate([FromBody] object requestBody)
        {

            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "編輯購物車失敗"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {
                var json = JsonConvert.SerializeObject(requestBody);

                if (json.Contains("quantity"))
                {
                    var request = JsonConvert.DeserializeObject<CartUpdateQuantityDto>(json);
                    // 處理 quantity 更新邏輯

                    if (db.Carts.Where(c => c.IsDeleted == false).Any(c => c.CartId == request.CartId))
                    {
                        var selCart = db.Carts.Where(c => c.IsDeleted == false && c.CartId == request.CartId).FirstOrDefault();

                        selCart.Quantity = request.Quantity;

                        db.SaveChanges();

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "成功編輯該購物車清單(quantity)",
                        };
                        return Ok(result);
                    }
                    else
                    {
                        var result = new
                        {
                            statusCode = 404,
                            status = false,
                            message = "購物車商品不存在",
                        };
                        return Ok(result);
                    }


                }
                else if (json.Contains("period"))
                {
                    var request = JsonConvert.DeserializeObject<CartUpdatePeriodDto>(json);
                    // 處理 period 更新邏輯

                    if (db.Carts.Where(c => c.IsDeleted == false).Any(c => c.CartId == request.CartId))
                    {
                        var selCart = db.Carts.Where(c => c.IsDeleted == false && c.CartId == request.CartId).FirstOrDefault();

                        selCart.Period = request.Period;
                        DateTime rentDate = (DateTime)selCart.RentDate;
                        selCart.ReturnDate = rentDate.AddDays(request.Period);

                        db.SaveChanges();

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "成功編輯該購物車清單(period)",
                        };
                        return Ok(result);
                    }
                    else
                    {
                        var result = new
                        {
                            statusCode = 404,
                            status = false,
                            message = "購物車商品不存在",
                        };
                        return Ok(result);
                    }


                }
                else if (json.Contains("rentStamp"))
                {
                    var request = JsonConvert.DeserializeObject<CartUpdateRentStampDto>(json);
                    // 處理 rentStamp 更新邏輯

                    if (DateTime.TryParse(request.RentStamp, out DateTime date))
                    {
                        // 如果轉換成功，將值賦給 selCart.RentDate

                        if (db.Carts.Where(c => c.IsDeleted == false).Any(c => c.CartId == request.CartId))
                        {
                            var selCart = db.Carts.Where(c => c.IsDeleted == false && c.CartId == request.CartId).FirstOrDefault();

                            int period = selCart.Period ?? 30;
                            selCart.RentDate = date;
                            selCart.ReturnDate = date.AddDays(period);

                            db.SaveChanges();

                            var result = new
                            {
                                statusCode = 200,
                                status = true,
                                message = "成功編輯該購物車清單(rentStamp)",
                            };
                            return Ok(result);
                        }

                        else
                        {
                            var result = new
                            {
                                statusCode = 404,
                                status = false,
                                message = "購物車商品不存在",
                            };
                            return Ok(result);
                        }

                    }
                    else
                    {
                        var result = new
                        {
                            statusCode = 400,
                            status = false,
                            message = "編輯該購物車清單(rentStamp)失敗",
                        };
                        return Ok(result);
                    }
                }
                else
                {
                    // 添加預設處理路徑
                    var invalidResult = new
                    {
                        statusCode = 400,
                        status = false,
                        message = "請求格式無效"
                    };
                    return Ok(invalidResult);
                }


            }
            catch (Exception ex)
            {
                var result = new
                {
                    statusCode = 500,
                    status = false,
                    message = "Server error",
                };
                return Ok(result);
            }

        }

        [HttpPut]
        [JwtAuthFilter]
        [Route("api/v1/cart/delete")]
        public IHttpActionResult CartDelete([FromBody] CartDeleteRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "刪除指定購物車失敗"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {
                if (db.Carts.Where(c => c.IsDeleted == false).Any(c => c.CartId == request.id))
                {
                    int userId = Convert.ToInt32(userToken["UserId"].ToString());


                    var selCart = db.Carts.Where(c => c.IsDeleted == false && c.UserId == userId).Where(c => c.CartId == request.id && c.ProductId == request.productId).FirstOrDefault();

                    selCart.IsDeleted = true;

                    db.SaveChanges();

                    var errorStr = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "成功刪除指定購物車"
                    };

                    return Ok(errorStr);

                }
                else
                {
                    var errorStr = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無指定購物車，刪除指定購物車失敗"
                    };

                    return Ok(errorStr);

                }

            }
            catch (Exception ex)
            {
                var result = new
                {
                    statusCode = 500,
                    status = false,
                    message = "Server error",
                };
                return Ok(result);
            }

        }










        #region 預設
        //// GET: api/Carts
        //public IQueryable<Cart> GetCarts()
        //{
        //    return db.Carts;
        //}

        //// GET: api/Carts/5
        //[ResponseType(typeof(Cart))]
        //public IHttpActionResult GetCart(int id)
        //{
        //    Cart cart = db.Carts.Find(id);
        //    if (cart == null)
        //    {
        //        return NotFound();
        //    }

        //    return Ok(cart);
        //}

        //// PUT: api/Carts/5
        //[ResponseType(typeof(void))]
        //public IHttpActionResult PutCart(int id, Cart cart)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    if (id != cart.CartId)
        //    {
        //        return BadRequest();
        //    }

        //    db.Entry(cart).State = EntityState.Modified;

        //    try
        //    {
        //        db.SaveChanges();
        //    }
        //    catch (DbUpdateConcurrencyException)
        //    {
        //        if (!CartExists(id))
        //        {
        //            return NotFound();
        //        }
        //        else
        //        {
        //            throw;
        //        }
        //    }

        //    return StatusCode(HttpStatusCode.NoContent);
        //}

        //// POST: api/Carts
        //[ResponseType(typeof(Cart))]
        //public IHttpActionResult PostCart(Cart cart)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    db.Carts.Add(cart);
        //    db.SaveChanges();

        //    return CreatedAtRoute("DefaultApi", new { id = cart.CartId }, cart);
        //}

        //// DELETE: api/Carts/5
        //[ResponseType(typeof(Cart))]
        //public IHttpActionResult DeleteCart(int id)
        //{
        //    Cart cart = db.Carts.Find(id);
        //    if (cart == null)
        //    {
        //        return NotFound();
        //    }

        //    db.Carts.Remove(cart);
        //    db.SaveChanges();

        //    return Ok(cart);
        //}

        //protected override void Dispose(bool disposing)
        //{
        //    if (disposing)
        //    {
        //        db.Dispose();
        //    }
        //    base.Dispose(disposing);
        //}

        //private bool CartExists(int id)
        //{
        //    return db.Carts.Count(e => e.CartId == id) > 0;
        //}
        #endregion
    }
}