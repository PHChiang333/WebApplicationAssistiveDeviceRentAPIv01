using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Http;
using WebApplicationAssistiveDeviceRentAPIv01.Class;
using WebApplicationAssistiveDeviceRentAPIv01.Models;

namespace WebApplicationAssistiveDeviceRentAPIv01.Controllers
{
    public class ProductsController : ApiController
    {
        private DBModel db = new DBModel();

        //string serverIp = @"http://52.172.145.130:8080";



        /// <summary>
        /// Get
        /// 查詢全部商品
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("api/v1/products")]
        public IHttpActionResult ProductsAll()
        {
            try
            {
                var products = db.Products.Where(p => p.IsDeleted == false);
                //分頁功能

                var result = new
                {
                    statusCode = 200,
                    status = true,
                    message = "查詢全部商品成功",
                    data = products.Where(p => p.IsDeleted == false).ToList().Select(p => new ProductsDto
                    {
                        id = p.ProductId,
                        type = p.GetProductTypeId.ProductTypeName ?? "",
                        name = p.ProductName ?? "",
                        level = p.ProductGMFMLvs?.FirstOrDefault(pg => pg.ProductId == p.ProductId)?.GMFMLvCode ?? "",
                        rent = p.Rent ?? -999999,
                        imgSrc = (ServerPath.Domain) + p.ProductImgs?.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview==true)?.ProductImgPath ?? "",
                        imgAlt = p.ProductName ?? "",
                        features = p.ProductFeatures.Where(pf => pf.ProductId == p.ProductId).Select(pf => pf.FeatureValue).ToArray()?? Array.Empty<string>(),
                        //.ProductFeatures.Where(pf => pf.ProductId == selProduct.ProductId).Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>(),
                        description = p.ProductDesc ??"",

                        

                        //第一種寫法:浩哥建議
                        //info = p.ProductInfos.Select(x => new
                        //{
                        //    infokey=x.ProductInfoKey,
                        //    infovalue=x.ProductInfoValue
                        //}),
                        //第二種寫法: 原定
                        //info = p.ProductInfos.Where(pi => pi.ProductId == p.ProductId).ToDictionary(pi => pi.ProductInfoKey, pi => pi.ProductInfoValue) ?? new Dictionary<string, string>(),

                    }
                    )
                };


                return Ok(result);
            }
            catch (Exception ex)
            {
                var result = new
                {
                    statusCode = 500,
                    status = true,
                    message = "伺服器錯誤",
                };


                return Ok(result);
            }

        }


        /// <summary>
        /// Get
        /// 查詢指定 string type,string lv 商品
        /// api/v1/products/filters?type=wheelchair&lv=0
        /// type=-1 表全部
        /// lv=-1 表全部
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("api/v1/products/filter")]
        public IHttpActionResult Products(string type, string lv)
        {
            //分頁功能?

            var products = db.Products.Where(p => p.IsDeleted == false);


            //if(!string.IsNullOrEmpty(type) && !string.IsNullOrEmpty(lv) && new[] { "-1", "1", "2", "3", "4", "5" }.Contains(lv) && products.Any(p => p.GetProductTypeId.ProductTypeName == type))
            if (!string.IsNullOrEmpty(type) && !string.IsNullOrEmpty(lv) && new[] { "-1", "1", "2", "3", "4", "5" }.Contains(lv))
            {
                if (products.Any(p => p.GetProductTypeId.ProductTypeName == type) || type == "-1")
                {
                    if (type == "-1" && lv == "-1")
                    {
                        //type為空 lv為空

                        products = db.Products.Where(p => p.IsDeleted == false);
                    }
                    else if (type != "-1" && lv == "-1")
                    {
                        //type不為空 lv為空
                        products = db.Products.Where(p => p.IsDeleted == false).Where(p => p.GetProductTypeId.ProductTypeName == type);
                    }
                    else if (type == "-1" && lv != "-1")
                    {
                        //type為空 lv不為空
                        products = db.Products.Where(p => p.IsDeleted == false).Where(p => p.ProductGMFMLvs.FirstOrDefault().GMFMLvCode == lv);
                    }
                    else
                    {
                        products = db.Products.Where(p => p.IsDeleted == false).Where(p => p.GetProductTypeId.ProductTypeName == type).Where(p => p.ProductGMFMLvs.FirstOrDefault().GMFMLvCode == lv);
                    }
                }
            }
            else
            {
                var error = new
                {
                    statusCode = 400,
                    status = false,
                    message = "錯誤的請求"
                };
                return Ok(error);
            }

            var result = new
            {
                statusCode = 200,
                status = true,
                message = "查詢全部商品成功",
                data = products.Where(p => p.IsDeleted == false).ToList().Select(p => new
                {
                    id = p.ProductId,
                    type = p.GetProductTypeId.ProductTypeName,
                    name = p.ProductName,
                    level = p.ProductGMFMLvs?.FirstOrDefault(pg => pg.ProductId == p.ProductId)?.GMFMLvCode ?? "",
                    rent = Convert.ToDouble(p.Rent),
                    deposit = Convert.ToDouble(p.Deposit),
                    fee = Convert.ToDouble(p.Fee),
                    description = p.ProductDesc ?? "",
                    //第一種寫法:浩哥建議
                    info = p.ProductInfos.Select(x => new
                    {
                        infokey = x.ProductInfoKey,
                        infovalue = x.ProductInfoValue
                    }),
                    //第二種寫法: 原定
                    //info = p.ProductInfos.Where(pi => pi.ProductId == p.ProductId).ToDictionary(pi => pi.ProductInfoKey, pi => pi.ProductInfoValue) ?? new Dictionary<string, string>(),

                    features = p.ProductFeatures.Where(pf => pf.ProductId == p.ProductId).Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>(),
                    image = new
                    {
                        preview = p.ProductImgs?.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview == true)?.ProductImgPath ?? "",
                        previewAlt = p.ProductName,
                        list = p.ProductImgs?.Where(pi => pi.IsDeleted == false && !pi.IsPreview)
                                .Select(pi => pi.ProductImgPath).ToArray() ?? Array.Empty<string>()
                    }
                }
                )
            };


            return Ok(result);
        }









        /// <summary>
        /// GET
        /// 以{商品id}查詢指定商品細節
        /// 
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("api/v1/products/{id}")]
        public IHttpActionResult Products(int id)
        {

            try
            {
                //找出未被刪除的data
                var products = db.Products.Where(p => p.IsDeleted == false);

                //確認有符合id 的data
                if (products.Any(p => p.ProductId == id))
                {
                    //var product = products.Where(p => p.ProductId == id).ToList().Select(p => new ProductDetailDto
                    var selProduct = products.FirstOrDefault(p => p.ProductId == id);


                    if (selProduct != null)
                    {
                        var product = new ProductDetailDto
                        {
                            id = selProduct.ProductId,
                            //type = productTypes.Where(pt => pt.ProductTypeId == p.ProductTypeId).Select(pt => pt.ProductTypeName).FirstOrDefault().ToString(),
                            type = selProduct.GetProductTypeId.ProductTypeName,
                            name = selProduct.ProductName,
                            //level = productGMFMLvs.Where(pg => pg.ProductId == selProduct.ProductId).Select(pg => pg.GMFMLvCode).Select(pgCode => int.TryParse(pgCode, out var codeFail) ? codeFail : 0).FirstOrDefault(),
                            level = selProduct.ProductGMFMLvs.FirstOrDefault(pg => pg.ProductId == selProduct.ProductId)?.GMFMLvCode ?? "",
                            rent = selProduct.Rent ?? 999999m,
                            deposit = selProduct.Deposit ?? 999999m,
                            fee = selProduct.Fee ?? 999999m,
                            description = selProduct.ProductDesc ?? "",
                            info = selProduct.ProductInfos.Where(pi => pi.ProductId == selProduct.ProductId).ToDictionary(pi => pi.ProductInfoKey, pi => pi.ProductInfoValue) ?? new Dictionary<string, string>(),
                            features = selProduct.ProductFeatures.Where(pf => pf.ProductId == selProduct.ProductId).Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>(),
                            image = new ImageDto
                            {
                                //preview = selProduct.ProductImgs.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview == true).ProductImgPath.ToString() ?? "",
                                //list = selProduct.ProductImgs.Where(pi => pi.IsDeleted == false && pi.IsPreview == false).Select(pi => pi.ProductImgPath).ToArray()
                                preview = (ServerPath.Domain)+ selProduct.ProductImgs?.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview)?.ProductImgPath ?? "",
                                previewAlt = selProduct.ProductImgs?.FirstOrDefault(pf => pf.IsDeleted == false && pf.IsPreview)?.ProductImgName ?? "",
                                list = selProduct.ProductImgs?.Where(pi => pi.IsDeleted == false && !pi.IsPreview)
                                .Select(pi => (ServerPath.Domain) + pi.ProductImgPath).ToArray() ?? Array.Empty<string>(),
                                listAlt = selProduct.ProductImgs?.Where(pi => pi.IsDeleted == false && !pi.IsPreview)
                                .Select(pi => pi.ProductImgName).ToArray() ?? Array.Empty<string>()

                            },
                            manual = selProduct.ProductManual ?? ""
                        };

                        int selTypeId = products.ToList().FirstOrDefault(p => p.ProductId == id).ProductTypeId;

                        var comparison = products.Where(p => p.ProductId != id).Where(p => p.ProductTypeId == selTypeId).OrderBy(p => Guid.NewGuid()).Take(4).ToList().Select(p => new comparisonDto
                        {
                            productId=p.ProductId,
                            imgSrc = (ServerPath.Domain) + p.ProductImgs?.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview)?.ProductImgPath ?? "",
                            name = p.ProductName ?? "",
                            rent = p.Rent ?? 999999m,
                            //material = p.ProductInfos.FirstOrDefault(pInfo => pInfo.ProductInfoKey == "material").ProductInfoValue ?? "",
                            material = p.ProductInfos.Where(pInfo => pInfo.ProductInfoKey == "material").FirstOrDefault()?.ProductInfoValue ?? "",
                            features = p.ProductFeatures.Select(pf => pf.FeatureValue).ToArray() ?? Array.Empty<string>()
                        });

                        var recommended = products.Where(p => p.ProductId != id).OrderBy(p => Guid.NewGuid()).Take(8).ToList().Select(p => new recommendedDto
                        {
                            productId = p.ProductId,
                            imgSrc = (ServerPath.Domain) + p.ProductImgs?.FirstOrDefault(pi => pi.IsDeleted == false && pi.IsPreview)?.ProductImgPath ?? "",
                            imgAlt = p.ProductName??"",
                            name = p.ProductName ?? "",
                            rent = p.Rent ?? 999999m,
                            features = p.ProductFeatures.Select(pf => pf.FeatureValue).ToArray()??Array.Empty<string>(),
                            description = p.ProductDesc??""
                        });


                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "查詢全部商品成功",
                            data = new
                            {
                                product,
                                comparison,
                                recommended
                            }
                        };


                        return Ok(result);

                    }
                    else
                    {
                        var error = new
                        {
                            statusCode = 404,
                            status = false,
                            message = "資源不存在"
                        };
                        return Ok(error);
                    }
                }
                else
                {
                    var error = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "資源不存在"
                    };
                    return Ok(error);
                }
            }
            catch (Exception ex)
            {

                var error = new
                {
                    statusCode = 500,
                    status = false,
                    message = "InternalServerError"
                };
                return Ok(error);
            }
        }




        #region Defaults
        // GET: api/Products
        //public IHttpActionResult GetProducts()
        //{
        //    var query = db.Products.Where(p => p.IsDeleted == false).Select(p => p).ToList();

        //    //var result = new ProductsDto{ 
        //    //   id = 1,
        //    //   name = query.


        //    //};

        //    return Ok(query);
        //}

        //// GET: api/Products/5
        //[ResponseType(typeof(Product))]
        //public IHttpActionResult GetProduct(int id)
        //{
        //    Product product = db.Products.Find(id);
        //    if (product == null)
        //    {
        //        return NotFound();
        //    }

        //    return Ok(product);
        //}

        //// PUT: api/Products/5
        //[ResponseType(typeof(void))]
        //public IHttpActionResult PutProduct(int id, Product product)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    if (id != product.ProductId)
        //    {
        //        return BadRequest();
        //    }

        //    db.Entry(product).State = EntityState.Modified;

        //    try
        //    {
        //        db.SaveChanges();
        //    }
        //    catch (DbUpdateConcurrencyException)
        //    {
        //        if (!ProductExists(id))
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

        //// POST: api/Products
        //[ResponseType(typeof(Product))]
        //public IHttpActionResult PostProduct(Product product)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    db.Products.Add(product);
        //    db.SaveChanges();

        //    return CreatedAtRoute("DefaultApi", new { id = product.ProductId }, product);
        //}

        //// DELETE: api/Products/5
        //[ResponseType(typeof(Product))]
        //public IHttpActionResult DeleteProduct(int id)
        //{
        //    Product product = db.Products.Find(id);
        //    if (product == null)
        //    {
        //        return NotFound();
        //    }

        //    db.Products.Remove(product);
        //    db.SaveChanges();

        //    return Ok(product);
        //}

        //protected override void Dispose(bool disposing)
        //{
        //    if (disposing)
        //    {
        //        db.Dispose();
        //    }
        //    base.Dispose(disposing);
        //}

        //private bool ProductExists(int id)
        //{
        //    return db.Products.Count(e => e.ProductId == id) > 0;
        //}
        #endregion
    }
}