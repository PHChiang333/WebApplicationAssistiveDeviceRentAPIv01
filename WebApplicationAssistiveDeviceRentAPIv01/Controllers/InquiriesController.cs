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
using WebApplicationAssistiveDeviceRentAPIv01.Class;
using WebApplicationAssistiveDeviceRentAPIv01.Models;
using WebApplicationAssistiveDeviceRentAPIv01.Models.Dto;
using WebApplicationAssistiveDeviceRentAPIv01.Security;

namespace WebApplicationAssistiveDeviceRentAPIv01.Controllers
{
    public class InquiriesController : ApiController
    {
        private DBModel db = new DBModel();



        /// <summary>
        /// 取得全部詢問單/建議單 (使用者後台)
        /// api/v1/member/inquiries
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [JwtAuthFilter]
        [Route("api/v1/member/inquiries")]
        public IHttpActionResult Inquiries()
        {
            //if (!ModelState.IsValid)
            //{
            //    var errorStr = new
            //    {
            //        statusCode = 400,
            //        status = false,
            //        message = "失敗"
            //    };

            //    return Ok(errorStr);
            //}

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {
                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                var selInquiries = db.Inquirys.Where(i => i.IsDeleted == false).Where(i => i.UserId == userId);


                var selData = selInquiries.ToList().Select(i => new InquiriesDto
                {
                    inquiryId = i.InquiryId,
                    inquiryCode = i.InquiryCode,
                    createdDate = i.CreateAt != null ? i.CreateAt : DateTime.MinValue,
                    createdStamp = i.CreateAt.ToString("yyyy-MM-dd") != null ? i.CreateAt.ToString("yyyy-MM-dd") : "",
                    isReplied = i.IsReplied ?? false,
                    images = i.InquiryProducts.Where(ip => ip.IsDeleted == false && ip.InquiryId == i.InquiryId).Select(ip => new InquiriesProductsDto
                    {
                        //src = ip.GetProductId.ProductImgs.Where(imgp => imgp.ProductId ==imgp.ProductId && imgp.IsPreview==true).Select(imgp => imgp.ProductImgPath).ToString(),
                        //src = ip.GetProductId.ProductImgs?.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview == true)?.ProductImgPath ?? "",
                        //alt = ip.GetProductId.ProductName

                        src = ip.GetProductId?.ProductImgs?.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview == true)?.ProductImgPath != null ? (ServerPath.Domain) + ip.GetProductId.ProductImgs.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview == true)?.ProductImgPath : "",
                        alt = ip.GetProductId?.ProductName ?? "" // 預設值
                    }).ToList(),
                    suggetsId = i.Suggests.Where(s => s.InquiryId == i.InquiryId).FirstOrDefault().SuggestId,
                    suggetsCode = i.Suggests.Where(s => s.InquiryId == i.InquiryId).FirstOrDefault().SuggestCode,
                }
                );


                var result = new
                {
                    statusCode = 200,
                    status = true,
                    message = "取得全部詢問單/建議單 (使用者後台)成功",
                    data = selData
                };

                return Ok(result);


                ////先確認User, UserInfo存在
                //if (db.Inquirys.Where(u => u.IsDeleted == false).ToList())
                //{



                //}
                //else
                //{
                //    //沒找到user

                //    var result = new
                //    {
                //        statusCode = 404,
                //        status = false,
                //        message = "no user exist."
                //    };
                //    return Ok(result);
                //}

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
        /// 添加詢問單
        /// api/v1/member/inquiry
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [JwtAuthFilter]
        [Route("api/v1/member/inquiry")]
        public IHttpActionResult InquiryAdd([FromBody] InquiryAddRequestDto request)
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

                //找到最新一筆需求單，找代碼
                var lastestInquiry = db.Inquirys.Where(i => i.IsDeleted == false).OrderByDescending(i => i.CreateAt).FirstOrDefault();

                string lastestInquiryCode;

                //第一次沒有單的情況
                if (lastestInquiry == null)
                {
                    lastestInquiryCode = "AA001";
                }
                else
                {
                    lastestInquiryCode = lastestInquiry.InquiryCode;
                }

                using (var transaction = db.Database.BeginTransaction())
                {
                    try
                    {
                        Inquiry inquiryAdd = new Inquiry();

                        inquiryAdd.InquiryCode = Function.GenerateNextOrderNumber(lastestInquiryCode);
                        inquiryAdd.UserId = userId;
                        inquiryAdd.IsReplied = false;
                        inquiryAdd.GMFMLvCode = request.level;
                        inquiryAdd.additionalInfo = request.additionalInfo;

                        inquiryAdd.CreateAt = DateTime.Now;
                        inquiryAdd.UpdateAt = DateTime.Now;
                        inquiryAdd.IsDeleted = false;
                        inquiryAdd.DeleteAt = null;

                        db.Inquirys.Add(inquiryAdd);
                        db.SaveChanges();

                        ////找到剛新增的詢問單Id  (用InquiryCode找)
                        //Inquiry inquiryAdded = db.Inquirys.FirstOrDefault(i => i.IsDeleted == false && i.UserId == userId && i.InquiryCode == inquiryAdd.InquiryCode);
                        //int inquiryId = inquiryAdded.InquiryId;


                        //// 使用剛新增的 InquiryId
                        int inquiryId = inquiryAdd.InquiryId;

                        var product = db.Products.Where(p => p.IsDeleted == false).Where(p => request.productIds.Contains(p.ProductId)).ToList();

                        for (int i = 0; i < request.productIds.Count; i++)
                        {
                            if (product.Any(p => p.ProductId == request.productIds[i]))
                            {
                                InquiryProduct inquiryProductAdd = new InquiryProduct();
                                inquiryProductAdd.InquiryId = inquiryId;
                                inquiryProductAdd.ProductId = request.productIds[i];
                                inquiryProductAdd.CreateAt = DateTime.Now;
                                inquiryProductAdd.UpdateAt = DateTime.Now;
                                inquiryProductAdd.IsDeleted = false;
                                inquiryProductAdd.DeleteAt = null;

                                db.InquiryProducts.Add(inquiryProductAdd);
                                db.SaveChanges();
                            }
                        }


                        // 同步新增對應的建議單

                        Suggest suggestAdd = new Suggest();

                        suggestAdd.SuggestCode = inquiryAdd.InquiryCode + "S";
                        suggestAdd.InquiryId = inquiryId;
                        //suggestAdd.GMFMLvCode = inquiryAdded.GMFMLvCode;
                        suggestAdd.GMFMLvCode = request.level;
                        suggestAdd.additionalInfo = "";
                        suggestAdd.IsSubmitted = false;
                        suggestAdd.CreateAt = DateTime.Now;
                        suggestAdd.UpdateAt = DateTime.Now;
                        suggestAdd.IsDeleted = false;
                        suggestAdd.DeleteAt = null;

                        db.Suggests.Add(suggestAdd);
                        db.SaveChanges();

                        // 提交交易
                        transaction.Commit();

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "添加詢問單成功",
                        };

                        return Ok(result);

                    }
                    catch (Exception ex) {
                        //  資料庫新增錯誤
                        // 回滾交易
                        transaction.Rollback();
                        var errorStr = new
                        {
                            statusCode = 400,
                            status = false,
                            message = "Bad request(資料庫新增錯誤)"
                        };

                        return Ok(errorStr);
                    }

                }


                #region 原本的  start  (如果request格式錯誤會造成db新增不同步)
                //原本的  start  (如果request格式錯誤會造成db新增不同步)
                //Inquiry inquiryAdd = new Inquiry();

                //inquiryAdd.InquiryCode = Function.GenerateNextOrderNumber(lastestInquiryCode);
                //inquiryAdd.UserId = userId;
                //inquiryAdd.IsReplied = false;
                //inquiryAdd.GMFMLvCode = request.level;
                //inquiryAdd.additionalInfo = request.additionalInfo;

                //inquiryAdd.CreateAt = DateTime.Now;
                //inquiryAdd.UpdateAt = DateTime.Now;
                //inquiryAdd.IsDeleted = false;
                //inquiryAdd.DeleteAt = null;

                //db.Inquirys.Add(inquiryAdd);
                //db.SaveChanges();

                //////找到剛新增的詢問單Id  (用InquiryCode找)
                ////Inquiry inquiryAdded = db.Inquirys.FirstOrDefault(i => i.IsDeleted == false && i.UserId == userId && i.InquiryCode == inquiryAdd.InquiryCode);
                ////int inquiryId = inquiryAdded.InquiryId;


                ////// 使用剛新增的 InquiryId
                //int inquiryId = inquiryAdd.InquiryId;

                //var product = db.Products.Where(p => p.IsDeleted == false).Where(p => request.productIds.Contains(p.ProductId)).ToList();

                //for (int i = 0; i < request.productIds.Count; i++)
                //{
                //    if (product.Any(p => p.ProductId == request.productIds[i]))
                //    {
                //        InquiryProduct inquiryProductAdd = new InquiryProduct();
                //        inquiryProductAdd.InquiryId = inquiryId;
                //        inquiryProductAdd.ProductId = request.productIds[i];
                //        inquiryProductAdd.CreateAt = DateTime.Now;
                //        inquiryProductAdd.UpdateAt = DateTime.Now;
                //        inquiryProductAdd.IsDeleted = false;
                //        inquiryProductAdd.DeleteAt = null;

                //        db.InquiryProducts.Add(inquiryProductAdd);
                //        db.SaveChanges();
                //    }
                //}


                ////TODO 會漏單
                //// 同步新增對應的建議單

                //Suggest suggestAdd = new Suggest();

                //suggestAdd.SuggestCode = inquiryAdd.InquiryCode + "S";
                //suggestAdd.InquiryId = inquiryId;
                ////suggestAdd.GMFMLvCode = inquiryAdded.GMFMLvCode;
                //suggestAdd.GMFMLvCode = request.level;
                //suggestAdd.additionalInfo = "";
                //suggestAdd.IsSubmitted = false;
                //suggestAdd.CreateAt = DateTime.Now;
                //suggestAdd.UpdateAt = DateTime.Now;
                //suggestAdd.IsDeleted = false;
                //suggestAdd.DeleteAt = null;

                //db.Suggests.Add(suggestAdd);
                //db.SaveChanges();
                //原本的  End  (如果request格式錯誤會造成db新增不同步)
                #endregion


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
        /// 取得未完成詢問單商品資料(使用者)
        /// api/v1/inquiry
        /// </summary>
        /// <returns></returns>
        //[HttpGet]
        [HttpPost]
        [JwtAuthFilter]
        [Route("api/v1/inquiry")]
        public IHttpActionResult InquiryUnfinished([FromBody] InquiryUnfinishedRequestDto request)
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

                var selData = new List<InquiryUnfinishedProductsDto>();

                var product = db.Products.Where(p => p.IsDeleted == false && request.productIds.Contains(p.ProductId)).ToList();

                for (int i = 0; i < request.productIds.Count; i++)
                {
                    var selProduct = product.Where(p => p.ProductId == request.productIds[i]).FirstOrDefault();

                    if (selProduct != null)
                    {
                        selData.Add(new InquiryUnfinishedProductsDto
                        {
                            id = selProduct.ProductId,
                            name = selProduct.ProductName,
                            description = selProduct.ProductDesc,
                            rent = selProduct.Rent ?? -99999,
                            imgSrc = (ServerPath.Domain) + selProduct.ProductImgs.Where(pimg => pimg.IsDeleted == false && pimg.IsPreview == true && pimg.ProductId == request.productIds[i]).FirstOrDefault()?.ProductImgPath ?? "",
                            imgAlt = selProduct.ProductName,
                            features = selProduct.ProductFeatures.Where(pf => pf.IsDeleted == false && pf.ProductId == request.productIds[i]).Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>()
                        });
                    }
                }

                var result = new
                {
                    statusCode = 200,
                    status = true,
                    message = "取得未完成詢問單商品資料(使用者)成功",
                    data = selData,
                };

                return Ok(result);
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
        /// 取得特定詢問單（帶單號）
        /// api/v1/inquiry
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        //[JwtAuthFilter]
        [Route("api/v1/inquiry/{InquiryCode}")]
        public IHttpActionResult InquiryByCode(string InquiryCode)
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


            try
            {
                string selInquiryCode = InquiryCode;


                var selInquiry = db.Inquirys.Where(i => i.IsDeleted == false).Where(i => i.InquiryCode == selInquiryCode).FirstOrDefault();

                //int userId = Convert.ToInt32(userToken["UserId"].ToString());

                if (selInquiry != null)
                {
                    //selInquiry存在
                    int selInquiryId = selInquiry.InquiryId;

                    //找到inquiry 中的productIds
                    var productIds = db.InquiryProducts.Where(ip => ip.IsDeleted == false && ip.InquiryId == selInquiryId).Select(ip => ip.ProductId).ToList();

                    var product = db.Products.Where(p => p.IsDeleted == false && productIds.Contains(p.ProductId)).ToList();

                    var productsInInquiry = new List<InquiryProductDto>();

                    for (int i = 0; i < productIds.Count; i++)
                    {
                        var selProduct = product.Where(p => p.ProductId == productIds[i]).FirstOrDefault();

                        if (selProduct != null)
                        {
                            productsInInquiry.Add(new InquiryProductDto
                            {
                                id = selProduct.ProductId,
                                name = selProduct.ProductName,
                                description = selProduct.ProductDesc,
                                rent = selProduct.Rent ?? -99999,
                                imgSrc = (ServerPath.Domain) + selProduct.ProductImgs.Where(pimg => pimg.IsDeleted == false && pimg.IsPreview == true && pimg.ProductId == productIds[i]).FirstOrDefault()?.ProductImgPath ?? "",
                                imgAlt = selProduct.ProductName,
                                features = selProduct.ProductFeatures.Where(pf => pf.IsDeleted == false && pf.ProductId == productIds[i]).Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>()
                            });
                        }
                    }

                    var selData = new InquiryDto
                    {
                        inquiryId = selInquiry.InquiryId,
                        inquiryCode = selInquiry.InquiryCode,
                        createdDate = selInquiry.CreateAt != null ? selInquiry.CreateAt : DateTime.MinValue,
                        createdStamp = selInquiry.CreateAt.ToString("yyyy-MM-dd") != null ? selInquiry.CreateAt.ToString("yyyy-MM-dd") : "",
                        level = selInquiry.GMFMLvCode,
                        additionalInfo = selInquiry.additionalInfo,
                        products = productsInInquiry
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
                        statusCode = 200,
                        status = false,
                        message = "無特定詢問單（帶單號）",
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
        /// 取得全部詢問單/建議單(店家後台)
        /// /api/v1/admin/inquiries
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [JwtAuthFilter]
        [Route("api/v1/admin/inquiries")]
        public IHttpActionResult InquiriesAdmin()
        {
            //if (!ModelState.IsValid)
            //{
            //    var errorStr = new
            //    {
            //        statusCode = 400,
            //        status = false,
            //        message = "失敗"
            //    };

            //    return Ok(errorStr);
            //}

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

                var inquirys = db.Inquirys.Where(i => i.IsDeleted == false).ToList();

                var selData = inquirys.Select(i => new InquiryByAdminDto
                {
                    inquiryId = i.InquiryId,
                    inquiryCode = i.InquiryCode,
                    isReplied = i.IsReplied ?? false,
                    createdDate = i.CreateAt != null ? i.CreateAt : DateTime.MinValue,
                    createdStamp = i.CreateAt.ToString("yyyy-MM-dd") != null ? i.CreateAt.ToString("yyyy-MM-dd") : "",
                    suggestId = (i.Suggests.FirstOrDefault() != null) ? i.Suggests.FirstOrDefault().SuggestId : -999,
                    suggestCode = (i.Suggests.FirstOrDefault() != null) ? i.Suggests.FirstOrDefault().SuggestCode : "",
                    member = new InquiryByAdminMemberDto
                    {
                        memberName = i.GetUserId.UserName,
                        email = i.GetUserId.UserEmail ?? "",
                        //TODO LineId記得要加
                        lineId = i.GetUserId.LineId ?? "",
                    }
                });

                var result = new
                {
                    statusCode = 200,
                    status = true,
                    message = "取得全部詢問單/建議單(店家後台)成功",
                    data = selData
                };

                return Ok(result);

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













        #region  default 


        //// GET: api/Inquiries
        //public IQueryable<Inquiry> GetInquirys()
        //{
        //    return db.Inquirys;
        //}

        //// GET: api/Inquiries/5
        //[ResponseType(typeof(Inquiry))]
        //public IHttpActionResult GetInquiry(int id)
        //{
        //    Inquiry inquiry = db.Inquirys.Find(id);
        //    if (inquiry == null)
        //    {
        //        return NotFound();
        //    }

        //    return Ok(inquiry);
        //}

        //// PUT: api/Inquiries/5
        //[ResponseType(typeof(void))]
        //public IHttpActionResult PutInquiry(int id, Inquiry inquiry)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    if (id != inquiry.InquiryId)
        //    {
        //        return BadRequest();
        //    }

        //    db.Entry(inquiry).State = EntityState.Modified;

        //    try
        //    {
        //        db.SaveChanges();
        //    }
        //    catch (DbUpdateConcurrencyException)
        //    {
        //        if (!InquiryExists(id))
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

        //// POST: api/Inquiries
        //[ResponseType(typeof(Inquiry))]
        //public IHttpActionResult PostInquiry(Inquiry inquiry)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    db.Inquirys.Add(inquiry);
        //    db.SaveChanges();

        //    return CreatedAtRoute("DefaultApi", new { id = inquiry.InquiryId }, inquiry);
        //}

        //// DELETE: api/Inquiries/5
        //[ResponseType(typeof(Inquiry))]
        //public IHttpActionResult DeleteInquiry(int id)
        //{
        //    Inquiry inquiry = db.Inquirys.Find(id);
        //    if (inquiry == null)
        //    {
        //        return NotFound();
        //    }

        //    db.Inquirys.Remove(inquiry);
        //    db.SaveChanges();

        //    return Ok(inquiry);
        //}

        //protected override void Dispose(bool disposing)
        //{
        //    if (disposing)
        //    {
        //        db.Dispose();
        //    }
        //    base.Dispose(disposing);
        //}

        //private bool InquiryExists(int id)
        //{
        //    return db.Inquirys.Count(e => e.InquiryId == id) > 0;
        //}



        #endregion

    }



}