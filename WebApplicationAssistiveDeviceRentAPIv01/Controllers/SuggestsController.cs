using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Description;
using System.Web.UI;
using WebApplicationAssistiveDeviceRentAPIv01.Class;
using WebApplicationAssistiveDeviceRentAPIv01.Models;
using WebApplicationAssistiveDeviceRentAPIv01.Models.Dto;
using WebApplicationAssistiveDeviceRentAPIv01.Security;

namespace WebApplicationAssistiveDeviceRentAPIv01.Controllers
{

    public class SuggestsController : ApiController
    {
        private DBModel db = new DBModel();

        /// <summary>
        /// 取得使用者特定建議單(帶單號)
        /// api/v1/suggest/{id}
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        //[JwtAuthFilter]
        [Route("api/v1/suggest/{suggestCode}")]
        public IHttpActionResult SuggestById(string suggestCode)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "Bad request"
                };

                return Ok(errorStr);
            }

            //var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);


            //只能找到已經送出的建議單


            try
            {
                var selSuggest = db.Suggests.Where(s => s.IsDeleted == false).Where(s => s.SuggestCode == suggestCode && s.IsSubmitted == true).FirstOrDefault();

                //int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (selSuggest != null)
                {
                    //selSuggestId這張單存在

                    int selSuggestId = selSuggest.SuggestId;

                    var selSuggestProducts = db.SuggestProducts.Where(sp => sp.IsDeleted == false && sp.SuggestId == selSuggestId).ToList() ?? new List<SuggestProduct>();

                    var selDataProducts = selSuggestProducts.Select(sp => new SuggestProductDto
                    {
                        id = sp.ProductId,
                        name = sp.GetProductId.ProductName ?? "",
                        description = sp.GetProductId.ProductDesc ?? "",
                        rent = sp.GetProductId.Rent ?? -99999,
                        imgSrc = (ServerPath.Domain) + sp.GetProductId.ProductImgs.Where(pimg => pimg.IsDeleted == false && pimg.ProductId == sp.ProductId && pimg.IsPreview == true).Select(pimg => pimg.ProductImgPath).FirstOrDefault() ?? "",
                        imgAlt = sp.GetProductId.ProductName ?? "",
                        features = sp.GetProductId.ProductFeatures.Where(pf => pf.IsDeleted == false && pf.ProductId == sp.ProductId).Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>(),
                        reasons = sp.Reasons ?? ""
                    }).ToList() ?? new List<SuggestProductDto>();


                    var selData = new SuggestDto
                    {
                        suggestId = selSuggest.SuggestId,
                        suggestCode = selSuggest.SuggestCode ?? "",
                        createdDate = selSuggest.CreateAt,
                        createdStamp = selSuggest.CreateAt.ToString("yyyy-MM-dd") ?? "",
                        additionalInfo = selSuggest.additionalInfo ?? "",
                        level = selSuggest.GMFMLvCode ?? "",
                        products = selDataProducts
                    };

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "取得特定詢問單（帶單號）成功",
                        data = selData,
                    };

                    return Ok(result);
                }
                else
                {

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無特定建議單（帶單號）",
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
                    message = "Server error"
                };
                return Ok(result);
            }
        }


        /// <summary>
        /// 取得特定建議單(by詢問單)(未送出)（店家後台）
        /// api/v1/admin/suggest
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [JwtAuthFilter]
        [Route("api/v1/admin/suggest")]
        public IHttpActionResult SuggestById(int inquiryId)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "Bad request"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {
                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (!db.User.Where(u => u.IsDeleted == false && u.IsAdmin == true).Any(u => u.UserId == userId))
                {
                    //不是管理員
                    var errorStr = new
                    {
                        statusCode = 401,
                        status = false,
                        message = "非管理員權限"
                    };

                    return Ok(errorStr);
                }

                //找到對應inquiryId的未送出的訂單
                var selSuggest = db.Suggests.Where(s => s.IsDeleted == false).Where(s => s.InquiryId == inquiryId && s.IsSubmitted == false).FirstOrDefault();

                //int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (selSuggest != null)
                {
                    //selSuggestId這張單存在

                    int selSuggestId = selSuggest.SuggestId;

                    var selSuggestProducts = db.SuggestProducts.Where(sp => sp.IsDeleted == false && sp.SuggestId == selSuggestId).ToList() ?? new List<SuggestProduct>();

                    var selDataProducts = selSuggestProducts.Select(sp => new SuggestNotSubmittedProductDto
                    {
                        suggestProductId = sp.SuggestProductId,
                        productId = sp.ProductId,
                        name = sp.GetProductId.ProductName,
                        description = sp.GetProductId.ProductDesc,
                        rent = sp.GetProductId.Rent ?? -99999,
                        imgSrc = (ServerPath.Domain) + sp.GetProductId.ProductImgs.Where(pimg => pimg.IsDeleted == false && pimg.ProductId == sp.ProductId && pimg.IsPreview == true).Select(pimg => pimg.ProductImgPath).FirstOrDefault() ?? "",
                        imgAlt = sp.GetProductId.ProductName ?? "",
                        features = sp.GetProductId.ProductFeatures.Where(pf => pf.IsDeleted == false && pf.ProductId == sp.ProductId).Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>(),
                        reasons = sp.Reasons
                    }).ToList() ?? new List<SuggestNotSubmittedProductDto>();


                    var selData = new SuggestNotSubmittedDto
                    {
                        suggestId = selSuggest.SuggestId,
                        suggestCode = selSuggest.SuggestCode,
                        level = selSuggest.GMFMLvCode,
                        additionalInfo = selSuggest.additionalInfo,
                        products = selDataProducts
                    };

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "取得特定詢問單（帶單號）成功",
                        data = selData,
                    };

                    return Ok(result);
                }
                else
                {

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無特定建議單（帶單號）",
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
                    message = "Server error"
                };
                return Ok(result);
            }
        }


        /// <summary>
        ///添加建議單商品
        /// api/v1/admin/suggest/product/
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [JwtAuthFilter]
        [Route("api/v1/admin/suggest/product/")]
        public IHttpActionResult SuggestAddProduct([FromBody] SuggestAddProductRequestdDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "Bad request"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {
                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (!db.User.Where(u => u.IsDeleted == false && u.IsAdmin == true).Any(u => u.UserId == userId))
                {
                    //不是管理員
                    var errorStr = new
                    {
                        statusCode = 401,
                        status = false,
                        message = "非管理員權限"
                    };

                    return Ok(errorStr);
                }

                //找到對應suggestId的未送出的訂單
                var selSuggest = db.Suggests.Where(s => s.IsDeleted == false).Where(s => s.SuggestId == request.suggestId && s.IsSubmitted == false).FirstOrDefault();

                var selProduct = db.Products.Where(s => s.IsDeleted == false).Where(p => p.ProductId == request.productId).FirstOrDefault();

                if (selProduct == null)
                {
                    //沒有這項product
                    var errorStr = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無指定商品"
                    };

                    return Ok(errorStr);
                }


                //int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (selSuggest != null)
                {
                    //selSuggestId這張單存在

                    var suggestProductAdd = new SuggestProduct();

                    suggestProductAdd.SuggestId = selSuggest.SuggestId;
                    suggestProductAdd.ProductId = selProduct.ProductId;
                    suggestProductAdd.Reasons = "";

                    suggestProductAdd.CreateAt = DateTime.Now;
                    suggestProductAdd.UpdateAt = DateTime.Now;
                    suggestProductAdd.IsDeleted = false;
                    suggestProductAdd.DeleteAt = null;

                    db.SuggestProducts.Add(suggestProductAdd);
                    db.SaveChanges();

                    //找到剛剛新增的單suggestProduct (找新增日期最新)

                    SuggestProduct suggestProductAdded = db.SuggestProducts.Where(sp => sp.IsDeleted == false).OrderByDescending(sp => sp.CreateAt).FirstOrDefault(sp => sp.SuggestId == selSuggest.SuggestId && sp.ProductId == selProduct.ProductId);

                    var selData = new SuggestAddProductDto
                    {
                        suggestProductId = suggestProductAdded.SuggestProductId,
                        product = new SuggestAddProductProductDto
                        {
                            id = selProduct.ProductId,
                            name = selProduct.ProductName ?? "",
                            description = selProduct.ProductDesc ?? "",
                            rent = selProduct.Rent ?? -9999,
                            imgSrc = (ServerPath.Domain) + selProduct.ProductImgs.Where(pimg => pimg.IsDeleted == false && pimg.ProductId == selProduct.ProductId && pimg.IsPreview == true).Select(pimg => pimg.ProductImgPath).FirstOrDefault() ?? "",
                            imgAlt = selProduct.ProductName ?? "",
                            features = selProduct.ProductFeatures.Where(pf => pf.IsDeleted == false && pf.ProductId == selProduct.ProductId).Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>(),
                            reasons = "",
                        }
                    };


                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "添加建議單商品成功",
                        data = selData,
                    };

                    return Ok(result);
                }
                else
                {

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無指定建議單",
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
                    message = "Server error"
                };
                return Ok(result);
            }
        }


        /// <summary>
        ///編輯建議單商品(info)
        /// api/v1/admin/suggest/product
        /// </summary>
        /// <returns></returns>
        [HttpPut]
        [JwtAuthFilter]
        [Route("api/v1/admin/suggest/product")]
        public IHttpActionResult SuggestUpdateProduct([FromBody] SuggestUpdateProductRequestdDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "Bad request"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {
                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (!db.User.Where(u => u.IsDeleted == false && u.IsAdmin == true).Any(u => u.UserId == userId))
                {
                    //不是管理員
                    var errorStr = new
                    {
                        statusCode = 401,
                        status = false,
                        message = "非管理員權限"
                    };

                    return Ok(errorStr);
                }

                //找到指定SuggestProduct
                var selSuggestProduct = db.SuggestProducts.Where(sp => sp.IsDeleted == false).Where(sp => sp.SuggestProductId == request.suggestProductId).FirstOrDefault();

                var selProduct = db.Products.Where(s => s.IsDeleted == false).Where(p => p.ProductId == request.productId).FirstOrDefault();

                if (selProduct == null)
                {
                    //沒有這項product
                    var errorStr = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無指定商品"
                    };

                    return Ok(errorStr);
                }


                //int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (selSuggestProduct != null)
                {
                    //selSuggestId這張單存在

                    selSuggestProduct.ProductId = selProduct.ProductId;
                    selSuggestProduct.Reasons = request.reasons;
                    selSuggestProduct.UpdateAt = DateTime.Now;

                    db.SaveChanges();

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "編輯建議單商品(info)成功",
                    };

                    return Ok(result);
                }
                else
                {

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "建議單中無指定商品",
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
                    message = "Server error"
                };
                return Ok(result);
            }
        }


        /// <summary>
        ///刪除建議單商品
        /// api/v1/admin/suggest/product
        /// </summary>
        /// <returns></returns>
        [HttpDelete]
        [JwtAuthFilter]
        [Route("api/v1/admin/suggest/product")]
        public IHttpActionResult SuggestDeleteProduct([FromBody] SuggestDeleteProductRequestdDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "Bad request"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {
                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (!db.User.Where(u => u.IsDeleted == false && u.IsAdmin == true).Any(u => u.UserId == userId))
                {
                    //不是管理員
                    var errorStr = new
                    {
                        statusCode = 401,
                        status = false,
                        message = "非管理員權限"
                    };

                    return Ok(errorStr);
                }

                //找到指定SuggestProduct
                var selSuggestProduct = db.SuggestProducts.Where(sp => sp.IsDeleted == false).Where(sp => sp.SuggestProductId == request.suggestProductId).FirstOrDefault();

                //int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (selSuggestProduct != null)
                {
                    //selSuggestId這張單存在
                    //Soft delete
                    selSuggestProduct.IsDeleted = true;
                    selSuggestProduct.DeleteAt = DateTime.Now;

                    db.SaveChanges();

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "刪除建議單商品成功",
                    };

                    return Ok(result);
                }
                else
                {

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "建議單中無指定商品",
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
                    message = "Server error"
                };
                return Ok(result);
            }
        }


        /// <summary>
        ///編輯建議單(上方資訊)
        /// api/v1/admin/suggest
        /// </summary>
        /// <returns></returns>
        [HttpPut]
        [JwtAuthFilter]
        [Route("api/v1/admin/suggest")]
        public IHttpActionResult SuggestUpdateInfo([FromBody] SuggestUpdateInfoRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "Bad request"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {
                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (!db.User.Where(u => u.IsDeleted == false && u.IsAdmin == true).Any(u => u.UserId == userId))
                {
                    //不是管理員
                    var errorStr = new
                    {
                        statusCode = 401,
                        status = false,
                        message = "非管理員權限"
                    };

                    return Ok(errorStr);
                }

                //找到指定Suggest
                var selSuggest = db.Suggests.Where(s => s.IsDeleted == false && s.IsSubmitted == false).Where(s => s.SuggestId == request.suggestId).FirstOrDefault();

                //int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (selSuggest != null)
                {
                    //selSuggestId這張單存在
                    //更新suggest
                    selSuggest.GMFMLvCode = request.level;
                    selSuggest.additionalInfo = request.additionalInfo;
                    selSuggest.IsSubmitted = request.isSubmitted;
                    selSuggest.UpdateAt = DateTime.Now;
                    //更新對應的inquiry
                    if (request.isSubmitted == true)
                    {
                        selSuggest.GetInquiryId.IsReplied = true;
                        selSuggest.GetInquiryId.UpdateAt = DateTime.Now;
                    }

                    db.SaveChanges();

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "編輯建議單(上方資訊)成功",
                    };

                    return Ok(result);
                }
                else
                {

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無指定建議單",
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
                    message = "Server error"
                };
                return Ok(result);
            }
        }








        #region 預設
        //// GET: api/Suggests
        //public IQueryable<Suggest> GetSuggests()
        //{
        //    return db.Suggests;
        //}

        //// GET: api/Suggests/5
        //[ResponseType(typeof(Suggest))]
        //public IHttpActionResult GetSuggest(int id)
        //{
        //    Suggest suggest = db.Suggests.Find(id);
        //    if (suggest == null)
        //    {
        //        return NotFound();
        //    }

        //    return Ok(suggest);
        //}

        //// PUT: api/Suggests/5
        //[ResponseType(typeof(void))]
        //public IHttpActionResult PutSuggest(int id, Suggest suggest)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    if (id != suggest.SuggestId)
        //    {
        //        return BadRequest();
        //    }

        //    db.Entry(suggest).State = EntityState.Modified;

        //    try
        //    {
        //        db.SaveChanges();
        //    }
        //    catch (DbUpdateConcurrencyException)
        //    {
        //        if (!SuggestExists(id))
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

        //// POST: api/Suggests
        //[ResponseType(typeof(Suggest))]
        //public IHttpActionResult PostSuggest(Suggest suggest)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    db.Suggests.Add(suggest);
        //    db.SaveChanges();

        //    return CreatedAtRoute("DefaultApi", new { id = suggest.SuggestId }, suggest);
        //}

        //// DELETE: api/Suggests/5
        //[ResponseType(typeof(Suggest))]
        //public IHttpActionResult DeleteSuggest(int id)
        //{
        //    Suggest suggest = db.Suggests.Find(id);
        //    if (suggest == null)
        //    {
        //        return NotFound();
        //    }

        //    db.Suggests.Remove(suggest);
        //    db.SaveChanges();

        //    return Ok(suggest);
        //}

        //protected override void Dispose(bool disposing)
        //{
        //    if (disposing)
        //    {
        //        db.Dispose();
        //    }
        //    base.Dispose(disposing);
        //}

        //private bool SuggestExists(int id)
        //{
        //    return db.Suggests.Count(e => e.SuggestId == id) > 0;
        //}

        #endregion



    }
}