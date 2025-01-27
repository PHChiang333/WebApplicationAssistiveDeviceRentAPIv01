using Microsoft.Owin.BuilderProperties;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Description;
//using System.Web.Mvc;
using WebApplicationAssistiveDeviceRentAPIv01.Class;
using WebApplicationAssistiveDeviceRentAPIv01.Models;
using WebApplicationAssistiveDeviceRentAPIv01.Models.Dto;
using WebApplicationAssistiveDeviceRentAPIv01.Models.Dto.LinePay;
using WebApplicationAssistiveDeviceRentAPIv01.Security;

namespace WebApplicationAssistiveDeviceRentAPIv01.Controllers
{
    public class OrdersController : ApiController
    {
        private DBModel db = new DBModel();
        private readonly LinePayService _linePayService = new LinePayService();


        /// <summary>
        /// 新增訂單
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost]
        [JwtAuthFilter]
        [Route("api/v0/orders")]
        public IHttpActionResult OrderAdd([FromBody] OrderRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "新增訂單失敗"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);


            try
            {
                //先確認cart存在
                if (db.Carts.Where(c => c.IsDeleted == false && c.IsTurnedOrder == false).Any(c => c.CartId == request.product.id))
                {
                    int userId = Convert.ToInt32(userToken["UserId"].ToString());

                    Cart SelCart = db.Carts.Where(c => c.IsDeleted == false && c.IsTurnedOrder == false).Where(c => c.CartId == request.product.id).FirstOrDefault() ?? new Cart();

                    SelCart.IsTurnedOrder = true;
                    SelCart.UpdateAt = DateTime.Now;

                    Product selProduct = db.Products.Where(p => p.IsDeleted == false && p.ProductId == SelCart.ProductId).FirstOrDefault();

                    Order OrderAdd = new Order();

                    string date = DateTime.Now.ToString("yyyyMMdd");

                    //處理序數  start
                    int serialNumber = db.Orders.Where(o => DbFunctions.TruncateTime(o.CreateAt) == DbFunctions.TruncateTime(DateTime.Now)).Count() + 1;

                    // 確保 serialNumber 是四位數，不足的補零；超過四位數時，拋出例外
                    if (serialNumber > 9999)
                    {
                        throw new InvalidOperationException("Serial number exceeds the maximum limit of 4 digits.");
                    }

                    // 格式化 serialNumber 為四位數字
                    string formattedSerialNumber = serialNumber.ToString("D4");

                    //處理序數  end

                    Random randoumN = new Random();
                    randoumN.Next();

                    OrderAdd.OrderCode = date + formattedSerialNumber;
                    OrderAdd.CartId = request.product.id;
                    OrderAdd.ProductName = request.product.name;
                    OrderAdd.ProductDesc = selProduct?.ProductDesc.ToString() ?? "";
                    //OrderAdd.Rent = selProduct?.Rent ?? -9999;
                    //OrderAdd.Deposit = selProduct?.Deposit ?? -99999;
                    OrderAdd.Rent = request.product.rent;
                    OrderAdd.Deposit = request.product.deposit;
                    OrderAdd.ImgSrc = request.product.imgSrc ?? "";
                    OrderAdd.shipping = request.shipping.method ?? "";
                    if (request.shipping.method == "store")
                    {
                        OrderAdd.ShippingStatus = "待取貨";
                    }
                    else
                    {
                        OrderAdd.ShippingStatus = "待出貨";
                    }
                    //OrderAdd.fee = selProduct?.Fee ?? -99999;
                    OrderAdd.fee = request.product.fee;
                    OrderAdd.Quantity = request.product.quantity;
                    OrderAdd.FinalAmount = request.product.finalAmount;
                    OrderAdd.Period = request.product.period;
                    OrderAdd.RentDate = (DateTime)request.product.rentStamp;
                    OrderAdd.ReturnDate = (DateTime)request.product.returnStamp;

                    OrderAdd.RecipientName = request.shipping.data.userName ?? string.Empty;
                    OrderAdd.RecipientPhone = request.shipping.data.phone;
                    OrderAdd.RecipientEmail = request.shipping.data.email;
                    OrderAdd.RecipientAddressZIP = request.shipping.data.addressZip;
                    OrderAdd.RecipientAddressCity = request.shipping.data.addressCity;
                    OrderAdd.RecipientAddressDistinct = request.shipping.data.addressDistrict;
                    OrderAdd.RecipientAddressDetail = request.shipping.data.addressDetail;
                    OrderAdd.PaymentBy = request.payment;
                    //預設值
                    OrderAdd.OrderStatus = "未付款";

                    //支付系統回復確認


                    //測試用: linePay 為已付款, CreditCard未付款
                    //bool isPaymentSuccess = false;

                    //if (request.payment == "LinePay")
                    //{
                    //    OrderAdd.OrderStatus = "已付款";
                    //    isPaymentSuccess = true;
                    //}
                    //else if (request.payment == "CreditCard")
                    //{
                    //    OrderAdd.OrderStatus = "未付款";
                    //}
                    //else
                    //{
                    //    OrderAdd.OrderStatus = "未付款";
                    //}




                    OrderAdd.note = "";
                    OrderAdd.EstimatedArrivalDate = "";
                    OrderAdd.PickupVerificationCode = date + serialNumber + Function.GenerateRandomCode();

                    //要記得加上基本設定
                    //要記得加上基本設定
                    //要記得加上基本設定
                    OrderAdd.CreateAt = DateTime.Now;
                    OrderAdd.UpdateAt = DateTime.Now;
                    OrderAdd.IsDeleted = false;
                    OrderAdd.DeleteAt = null;



                    db.Orders.Add(OrderAdd);
                    db.SaveChanges();


                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "添加訂單成功",
                        //isPaymentSuccess = isPaymentSuccess
                    };

                    return Ok(result);
                }
                else
                {
                    //沒找到cart

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "添加訂單失敗(無指定購物車)"
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
        /// 新增訂單v2 (含LinePay) 
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost]
        [JwtAuthFilter]
        [Route("api/v2/orders")]
        public async Task<IHttpActionResult> OrderAddPayment([FromBody] OrderRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "新增訂單失敗"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);


            try
            {
                //先確認cart存在
                if (db.Carts.Where(c => c.IsDeleted == false && c.IsTurnedOrder == false).Any(c => c.CartId == request.product.id))
                {
                    int userId = Convert.ToInt32(userToken["UserId"].ToString());

                    Cart SelCart = db.Carts.Where(c => c.IsDeleted == false && c.IsTurnedOrder == false).Where(c => c.CartId == request.product.id).FirstOrDefault() ?? new Cart();

                    SelCart.IsTurnedOrder = true;
                    SelCart.UpdateAt = DateTime.Now;

                    Product selProduct = db.Products.Where(p => p.IsDeleted == false && p.ProductId == SelCart.ProductId).FirstOrDefault();

                    Order OrderAdd = new Order();

                    string date = DateTime.Now.ToString("yyyyMMdd");

                    //處理序數  start
                    int serialNumber = db.Orders.Where(o => DbFunctions.TruncateTime(o.CreateAt) == DbFunctions.TruncateTime(DateTime.Now)).Count() + 1;

                    // 確保 serialNumber 是四位數，不足的補零；超過四位數時，拋出例外
                    if (serialNumber > 9999)
                    {
                        throw new InvalidOperationException("Serial number exceeds the maximum limit of 4 digits.");
                    }

                    // 格式化 serialNumber 為四位數字
                    string formattedSerialNumber = serialNumber.ToString("D4");

                    //處理序數  end

                    Random randoumN = new Random();
                    randoumN.Next();

                    OrderAdd.OrderCode = date + formattedSerialNumber;
                    OrderAdd.CartId = request.product.id;
                    OrderAdd.ProductName = request.product.name;
                    OrderAdd.ProductDesc = selProduct?.ProductDesc.ToString() ?? "";
                    //OrderAdd.Rent = selProduct?.Rent ?? -9999;
                    //OrderAdd.Deposit = selProduct?.Deposit ?? -99999;
                    OrderAdd.Rent = request.product.rent;
                    OrderAdd.Deposit = request.product.deposit;
                    OrderAdd.ImgSrc = request.product.imgSrc ?? "";
                    OrderAdd.shipping = request.shipping.method ?? "";
                    if (request.shipping.method == "store")
                    {
                        OrderAdd.ShippingStatus = "待取貨";
                    }
                    else
                    {
                        OrderAdd.ShippingStatus = "待出貨";
                    }
                    //OrderAdd.fee = selProduct?.Fee ?? -99999;
                    OrderAdd.fee = request.product.fee;
                    OrderAdd.Quantity = request.product.quantity;
                    OrderAdd.FinalAmount = request.product.finalAmount;
                    OrderAdd.Period = request.product.period;
                    OrderAdd.RentDate = (DateTime)request.product.rentStamp;
                    OrderAdd.ReturnDate = (DateTime)request.product.returnStamp;

                    OrderAdd.RecipientName = request.shipping.data.userName ?? string.Empty;
                    OrderAdd.RecipientPhone = request.shipping.data.phone;
                    OrderAdd.RecipientEmail = request.shipping.data.email;
                    OrderAdd.RecipientAddressZIP = request.shipping.data.addressZip;
                    OrderAdd.RecipientAddressCity = request.shipping.data.addressCity;
                    OrderAdd.RecipientAddressDistinct = request.shipping.data.addressDistrict;
                    OrderAdd.RecipientAddressDetail = request.shipping.data.addressDetail;
                    OrderAdd.PaymentBy = request.payment;
                    //預設值
                    OrderAdd.OrderStatus = "未付款";

                    //支付系統回復確認


                    //測試用: linePay 為已付款, CreditCard未付款
                    //bool isPaymentSuccess = false;

                    //if (request.payment == "LinePay")
                    //{
                    //    OrderAdd.OrderStatus = "已付款";
                    //    isPaymentSuccess = true;
                    //}
                    //else if (request.payment == "CreditCard")
                    //{
                    //    OrderAdd.OrderStatus = "未付款";
                    //}
                    //else
                    //{
                    //    OrderAdd.OrderStatus = "未付款";
                    //}




                    OrderAdd.note = "";
                    OrderAdd.EstimatedArrivalDate = "";
                    OrderAdd.PickupVerificationCode = date + serialNumber + Function.GenerateRandomCode();

                    //要記得加上基本設定
                    //要記得加上基本設定
                    //要記得加上基本設定
                    OrderAdd.CreateAt = DateTime.Now;
                    OrderAdd.UpdateAt = DateTime.Now;
                    OrderAdd.IsDeleted = false;
                    OrderAdd.DeleteAt = null;



                    db.Orders.Add(OrderAdd);
                    db.SaveChanges();

                    //支付
                    //錯誤訊息用
                    string PaymentAppMsg = "";

                    if (request.payment == "LinePay")
                    {

                        try
                        {
                            //PaymentAppMsg += "測試點00";

                            //確認訂單
                            var selOrder = db.Orders.Where(o => o.IsDeleted == false && o.CartId == request.product.id).FirstOrDefault();

                            //PaymentAppMsg += "測試點01";
                            //new linePayReserve 的 LinePayRequestDto
                            LinePayRequestDto linePayReserveRequest = new LinePayRequestDto
                            {
                                amount = (int)(selOrder.FinalAmount),//訂單價格
                                //currency 已經設定為唯讀
                                orderId = selOrder.OrderId.ToString(),
                                packages = new List<PackageDto>
                                {
                                    new PackageDto
                                    {
                                        id=selOrder.OrderId.ToString(),
                                        amount = (int)(selOrder.FinalAmount), //訂單價格
                                        name = selOrder.ProductName,
                                        products=new List<ProductDto>
                                        {
                                            new ProductDto
                                            {
                                                name = selOrder.ProductName,
                                                quantity = 1,  //直接用訂單數量
                                                price = (int)selOrder.FinalAmount,  //訂單價格
                                            }
                                        }

                                    }
                                },
                                redirectUrls = new RedirectUrlsDto
                                {
                                    confirmUrl = "https://assist-hub.vercel.app/cart/checkout/confirm",
                                    cancelUrl = "https://assist-hub.vercel.app/cart/checkout/declined"
                                }

                            };

                            //PaymentAppMsg += "測試點02";


                            //發送request 並接收response
                            var resultLinePayReserve = await _linePayService.ReservePaymentAsync(linePayReserveRequest);

                            selOrder.TransactionId = resultLinePayReserve.info.transactionId.ToString();
                            db.SaveChanges();

                            //PaymentAppMsg += "測試點03";

                            //response成功
                            if (resultLinePayReserve.returnCode == "0000")
                            {

                                string transactionId = resultLinePayReserve.info.transactionId.ToString();

                                var selData = new
                                {
                                    linePay = new
                                    {
                                        LinePayReturnCode = resultLinePayReserve.returnCode,
                                        transactionId = transactionId,
                                        finalAmount = linePayReserveRequest.amount,  //提供訂單確認用
                                        PaymentUrl = new
                                        {
                                            web = resultLinePayReserve.info.paymentUrl.web,
                                            app = resultLinePayReserve.info.paymentUrl.app,
                                        }
                                    }
                                };


                                PaymentAppMsg += "LinePay 訂單發送成功，請付款";


                                var result = new
                                {
                                    statusCode = 200,
                                    status = true,
                                    message = "添加訂單成功" + ", " + PaymentAppMsg,
                                    data = selData,
                                    linePayReturnCode = resultLinePayReserve.returnCode,
                                };
                                return Ok(result);
                            }
                            else
                            {
                                //其他的requestCode
                                PaymentAppMsg += "LinePay 訂單發送成功，LinePay端異常";

                                var result = new
                                {
                                    statusCode = 200,
                                    status = true,
                                    message = "添加訂單成功" + ", " + PaymentAppMsg,
                                    linePayReturnCode = resultLinePayReserve.returnCode,

                                };
                                return Ok(result);
                            }
                        }
                        catch (Exception ex)
                        {
                            //LinePAyReserve fail
                            PaymentAppMsg = "LinePay 訂單發送失敗";

                            var result = new
                            {
                                statusCode = 200,
                                status = true,
                                message = "添加訂單成功" + ", " + PaymentAppMsg,
                                errorlog = ex


                            };
                            return Ok(result);

                        }
                    }
                    else if (request.payment == "creditCard")
                    {
                        // LinePay, creditCard, transfer
                        PaymentAppMsg = "信用卡支付";

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "添加訂單成功" + ", " + PaymentAppMsg,

                        };
                        return Ok(result);


                    }
                    else if (request.payment == "transfer")
                    {
                        // LinePay, creditCard, transfer

                        PaymentAppMsg = "轉帳支付";

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "添加訂單成功" + ", " + PaymentAppMsg,

                        };
                        return Ok(result);
                    }
                    else
                    {
                        PaymentAppMsg = "";

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "添加訂單成功" + ", " + PaymentAppMsg,

                        };
                        return Ok(result);
                    }




                }
                else
                {
                    //沒找到cart

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "添加訂單失敗(無指定購物車)"
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
        /// 新增訂單v3 (含LinePay)測試querystring
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost]
        [JwtAuthFilter]
        [Route("api/v1/orders")]
        public async Task<IHttpActionResult> OrderAddPayment02([FromBody] OrderRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "新增訂單失敗"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);



            try
            {
                //先確認cart存在
                if (db.Carts.Where(c => c.IsDeleted == false && c.IsTurnedOrder == false).Any(c => c.CartId == request.product.id))
                {
                    int userId = Convert.ToInt32(userToken["UserId"].ToString());

                    Cart SelCart = db.Carts.Where(c => c.IsDeleted == false && c.IsTurnedOrder == false).Where(c => c.CartId == request.product.id).FirstOrDefault() ?? new Cart();

                    SelCart.IsTurnedOrder = true;
                    SelCart.UpdateAt = DateTime.Now;

                    Product selProduct = db.Products.Where(p => p.IsDeleted == false && p.ProductId == SelCart.ProductId).FirstOrDefault();

                    Order OrderAdd = new Order();

                    string date = DateTime.Now.ToString("yyyyMMdd");

                    //處理序數  start
                    int serialNumber = db.Orders.Where(o => DbFunctions.TruncateTime(o.CreateAt) == DbFunctions.TruncateTime(DateTime.Now)).Count() + 1;

                    // 確保 serialNumber 是四位數，不足的補零；超過四位數時，拋出例外
                    if (serialNumber > 9999)
                    {
                        throw new InvalidOperationException("Serial number exceeds the maximum limit of 4 digits.");
                    }

                    // 格式化 serialNumber 為四位數字
                    string formattedSerialNumber = serialNumber.ToString("D4");

                    //處理序數  end

                    Random randoumN = new Random();
                    randoumN.Next();

                    OrderAdd.OrderCode = date + formattedSerialNumber;
                    OrderAdd.CartId = request.product.id;
                    OrderAdd.ProductName = request.product.name;
                    OrderAdd.ProductDesc = selProduct?.ProductDesc.ToString() ?? "";
                    //OrderAdd.Rent = selProduct?.Rent ?? -9999;
                    //OrderAdd.Deposit = selProduct?.Deposit ?? -99999;
                    OrderAdd.Rent = request.product.rent;
                    OrderAdd.Deposit = request.product.deposit;
                    OrderAdd.ImgSrc = request.product.imgSrc ?? "";
                    OrderAdd.shipping = request.shipping.method ?? "";
                    if (request.shipping.method == "store")
                    {
                        OrderAdd.ShippingStatus = "待取貨";
                    }
                    else
                    {
                        OrderAdd.ShippingStatus = "待出貨";
                    }
                    //OrderAdd.fee = selProduct?.Fee ?? -99999;
                    OrderAdd.fee = request.product.fee;
                    OrderAdd.Quantity = request.product.quantity;
                    OrderAdd.FinalAmount = request.product.finalAmount;
                    OrderAdd.Period = request.product.period;
                    OrderAdd.RentDate = (DateTime)request.product.rentStamp;
                    OrderAdd.ReturnDate = (DateTime)request.product.returnStamp;

                    OrderAdd.RecipientName = request.shipping.data.userName ?? string.Empty;
                    OrderAdd.RecipientPhone = request.shipping.data.phone;
                    OrderAdd.RecipientEmail = request.shipping.data.email;
                    OrderAdd.RecipientAddressZIP = request.shipping.data.addressZip;
                    OrderAdd.RecipientAddressCity = request.shipping.data.addressCity;
                    OrderAdd.RecipientAddressDistinct = request.shipping.data.addressDistrict;
                    OrderAdd.RecipientAddressDetail = request.shipping.data.addressDetail;
                    OrderAdd.PaymentBy = request.payment;
                    //預設值
                    OrderAdd.OrderStatus = "未付款";

                    //支付系統回復確認


                    //測試用: linePay 為已付款, CreditCard未付款
                    //bool isPaymentSuccess = false;

                    //if (request.payment == "LinePay")
                    //{
                    //    OrderAdd.OrderStatus = "已付款";
                    //    isPaymentSuccess = true;
                    //}
                    //else if (request.payment == "CreditCard")
                    //{
                    //    OrderAdd.OrderStatus = "未付款";
                    //}
                    //else
                    //{
                    //    OrderAdd.OrderStatus = "未付款";
                    //}




                    OrderAdd.note = "";
                    OrderAdd.EstimatedArrivalDate = "";
                    OrderAdd.PickupVerificationCode = date + serialNumber + Function.GenerateRandomCode();

                    //要記得加上基本設定
                    //要記得加上基本設定
                    //要記得加上基本設定
                    OrderAdd.CreateAt = DateTime.Now;
                    OrderAdd.UpdateAt = DateTime.Now;
                    OrderAdd.IsDeleted = false;
                    OrderAdd.DeleteAt = null;



                    db.Orders.Add(OrderAdd);
                    db.SaveChanges();

                    //支付
                    //錯誤訊息用
                    string PaymentAppMsg = "";

                    if (request.payment == "LinePay")
                    {
                        //TODO 確認LinePay
                        string selConfirmUrl = request.confirmUrl;
                        string selCancelUrl = "https://assist-hub.vercel.app/cart/checkout/declined";

                        try
                        {
                            //PaymentAppMsg += "測試點00";

                            //確認訂單
                            var selOrder = db.Orders.Where(o => o.IsDeleted == false && o.CartId == request.product.id).FirstOrDefault();

                            //PaymentAppMsg += "測試點01";
                            //new linePayReserve 的 LinePayRequestDto
                            LinePayRequestDto linePayReserveRequest = new LinePayRequestDto
                            {
                                amount = (int)(selOrder.FinalAmount),//訂單價格
                                //currency 已經設定為唯讀
                                orderId = selOrder.OrderId.ToString(),
                                packages = new List<PackageDto>
                                {
                                    new PackageDto
                                    {
                                        id=selOrder.OrderId.ToString(),
                                        amount = (int)(selOrder.FinalAmount), //訂單價格
                                        name = selOrder.ProductName,
                                        products=new List<ProductDto>
                                        {
                                            new ProductDto
                                            {
                                                name = selOrder.ProductName,
                                                quantity = 1,  //直接用訂單數量
                                                price = (int)selOrder.FinalAmount,  //訂單價格
                                            }
                                        }

                                    }
                                },
                                redirectUrls = new RedirectUrlsDto
                                {
                                    confirmUrl = selConfirmUrl,
                                    cancelUrl = selCancelUrl,
                                }

                            };

                            //PaymentAppMsg += "測試點02";


                            //發送request 並接收response
                            var resultLinePayReserve = await _linePayService.ReservePaymentAsync(linePayReserveRequest);

                            selOrder.TransactionId = resultLinePayReserve.info.transactionId.ToString();
                            db.SaveChanges();

                            //PaymentAppMsg += "測試點03";

                            //response成功
                            if (resultLinePayReserve.returnCode == "0000")
                            {

                                string transactionId = resultLinePayReserve.info.transactionId.ToString();

                                var selData = new
                                {
                                    linePay = new
                                    {
                                        LinePayReturnCode = resultLinePayReserve.returnCode,
                                        transactionId = transactionId,
                                        orderId = selOrder.OrderId,
                                        finalAmount = linePayReserveRequest.amount,  //提供訂單確認用
                                        PaymentUrl = new
                                        {
                                            web = resultLinePayReserve.info.paymentUrl.web,
                                            app = resultLinePayReserve.info.paymentUrl.app,
                                        }
                                    }
                                };


                                PaymentAppMsg += " LinePay 訂單發送成功，請付款";


                                var result = new
                                {
                                    statusCode = 200,
                                    status = true,
                                    message = "添加訂單成功" + ", " + PaymentAppMsg,
                                    data = selData,
                                    linePayReturnCode = resultLinePayReserve.returnCode,
                                };





                                string queryString = $"?transactionId={transactionId}&finalAmount={linePayReserveRequest.amount}";
                                //string baseUrl = "https://assist-hub.vercel.app/api/tesx";
                                string baseUrl = selConfirmUrl;
                                string fullUrl = baseUrl + queryString;



                                // 建立 HttpResponseMessage 並設置 Location 標頭
                                var response = Request.CreateResponse(System.Net.HttpStatusCode.OK, result);
                                response.Headers.Location = new Uri(fullUrl);

                                return ResponseMessage(response);
                                //return Ok(result);
                            }
                            else
                            {
                                //其他的requestCode
                                PaymentAppMsg += "LinePay 訂單發送成功，LinePay端異常";

                                var result = new
                                {
                                    statusCode = 200,
                                    status = true,
                                    message = "添加訂單成功" + ", " + PaymentAppMsg,
                                    linePayReturnCode = resultLinePayReserve.returnCode,

                                };
                                return Ok(result);
                            }
                        }
                        catch (Exception ex)
                        {
                            //LinePAyReserve fail
                            PaymentAppMsg = "LinePay 訂單發送失敗";

                            var result = new
                            {
                                statusCode = 200,
                                status = true,
                                message = "添加訂單成功" + ", " + PaymentAppMsg,
                                errorlog = ex


                            };
                            return Ok(result);

                        }
                    }
                    else if (request.payment == "creditCard")
                    {
                        // LinePay, creditCard, transfer
                        PaymentAppMsg = "信用卡支付";

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "添加訂單成功" + ", " + PaymentAppMsg,

                        };
                        return Ok(result);


                    }
                    else if (request.payment == "transfer")
                    {
                        // LinePay, creditCard, transfer

                        PaymentAppMsg = "轉帳支付";

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "添加訂單成功" + ", " + PaymentAppMsg,

                        };
                        return Ok(result);
                    }
                    else
                    {
                        PaymentAppMsg = "";

                        var result = new
                        {
                            statusCode = 200,
                            status = true,
                            message = "添加訂單成功" + ", " + PaymentAppMsg,

                        };
                        return Ok(result);
                    }




                }
                else
                {
                    //沒找到cart

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "添加訂單失敗(無指定購物車)"
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
        /// 取得會員訂單(全部)
        /// 'api/v1/members/order/'
        /// 帶入JWT 驗證
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [JwtAuthFilter]
        [Route("api/v1/members/orders")]
        public IHttpActionResult Orders()
        {
            //if (!ModelState.IsValid)
            //{
            //    var errorStr = new
            //    {
            //        statusCode = 400,
            //        status = false,
            //        message = "新增訂單失敗"
            //    };

            //    return Ok(errorStr);
            //}

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {

                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                var selOrders = db.Orders.Where(o => o.IsDeleted == false).Where(o => o.GetCartId.UserId == userId);

                var selData = selOrders.ToList().Select(o => new OrdersDto
                {
                    orderId = o.OrderId,
                    memberName = o.GetCartId.GetUserId.UserName,
                    orderStatus = o.OrderStatus ?? "",
                    shippingStatus = o.ShippingStatus ?? "",
                    orderCode = o.OrderCode ?? "",
                    createdDate = o.CreateAt != null ? o.CreateAt : DateTime.MinValue,
                    createdStamp = o.CreateAt.ToString("yyyy-MM-dd") ?? "",
                    shipping = o.shipping ?? "",
                    details = new OrdersDetailsDto
                    {
                        quantity = o.Quantity ?? -99999,
                        productName = o.ProductName,
                        productDes = o.ProductDesc,
                        //productImgSrc = (ServerPath.Domain) + o.ImgSrc,
                        productImgSrc = o.ImgSrc,   //建立訂單的時候已經是完整path
                        productImgAlt = o.ProductName,
                        rent = o.Rent ?? -99999,
                        deposit = o.Deposit ?? -99999,
                        fee = o.fee ?? -99999,
                        //feeDeposit = o.fee ??-99999 + o.Deposit ?? -99999,  //前端計算
                        finalAmount = o.FinalAmount ?? -99999,
                        rentDate = o.RentDate ?? DateTime.MinValue,
                        rentStamp = (o.RentDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                        returnDate = o.ReturnDate ?? DateTime.MinValue,
                        returnStamp = (o.ReturnDate ?? DateTime.MinValue).ToString("yyyy-MM-dd")

                    }

                });



                var result = new
                {
                    statusCode = 200,
                    status = true,
                    message = "成功取得會員訂單",
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


        /// <summary>
        /// 取得指定訂單(細節)
        /// 'api/v1/members/order/{id}' ex:api/v1/members/order/11
        /// 帶入JWT 驗證
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [JwtAuthFilter]
        [Route("api/v1/members/order/{id}")]
        public IHttpActionResult Orders(int id)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "取得訂單(細節)失敗，bad request"
                };

                return Ok(errorStr);
            }

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            int selOrderId = id;

            try
            {
                if (db.Orders.Where(o => o.IsDeleted == false).Any(o => o.OrderId == selOrderId))
                {
                    int userId = Convert.ToInt32(userToken["UserId"].ToString());

                    //陣列版本
                    //var selOrders = db.Orders.Where(o => o.IsDeleted == false).Where(o => o.GetCartId.UserId == userId).Where(o => o.OrderId == selOrderId);

                    //var selData = selOrders.ToList().Select(o => new OrderDetailDto
                    //{
                    //    orderStatus = o.OrderStatus ?? "",
                    //    shippingStatus = o.ShippingStatus ?? "",
                    //    orderCode = o.OrderCode ?? "",
                    //    createdDate = o.CreateAt != null ? o.CreateAt : DateTime.MinValue,
                    //    createdStamp = o.CreateAt.ToString("yyyy-MM-dd") ?? "",
                    //    note = o.note ?? "",
                    //    shipping = o.shipping ?? "",
                    //    shippinginfo = new OrderDetailShippingInfoDto
                    //    {
                    //        name = o.RecipientName,
                    //        phone = o.RecipientPhone,
                    //        email = o.RecipientEmail,
                    //        address = o.RecipientAddressCity + o.RecipientAddressDistinct + o.RecipientAddressDetail
                    //    },
                    //    details = new OrderDetailDetailsDto
                    //    {
                    //        quantity = o.Quantity ?? -99999,
                    //        productName = o.ProductName,
                    //        productDes = o.ProductDesc,
                    //        productImgSrc = (ServerPath.Domain) + o.ImgSrc,
                    //        productImgAlt = o.ProductName,
                    //        rent = o.Rent ?? -99999,
                    //        deposit = o.Deposit ?? -99999,
                    //        fee = o.fee ?? -99999,
                    //        //feeDeposit = o.fee ??-99999 + o.Deposit ?? -99999,  //前端計算
                    //        finalAmount = o.FinalAmount ?? -99999,
                    //        period = o.Period,
                    //        rentDate = o.RentDate ?? DateTime.MinValue,
                    //        rentStamp = (o.RentDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                    //        returnDate = o.ReturnDate ?? DateTime.MinValue,
                    //        returnStamp = (o.ReturnDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                    //        payment = o.PaymentBy
                    //    }

                    //});

                    //物件版本
                    var selOrder = db.Orders.Where(o => o.IsDeleted == false).Where(o => o.GetCartId.UserId == userId).Where(o => o.OrderId == selOrderId).FirstOrDefault();

                    var selData = new OrderDetailDto
                    {
                        orderStatus = selOrder.OrderStatus ?? "",
                        shippingStatus = selOrder.ShippingStatus ?? "",
                        orderCode = selOrder.OrderCode ?? "",
                        createdDate = selOrder.CreateAt != null ? selOrder.CreateAt : DateTime.MinValue,
                        createdStamp = selOrder.CreateAt.ToString("yyyy-MM-dd") ?? "",
                        note = selOrder.note ?? "",
                        shipping = selOrder.shipping ?? "",
                        shippinginfo = new OrderDetailShippingInfoDto
                        {
                            name = selOrder.RecipientName,
                            phone = selOrder.RecipientPhone,
                            email = selOrder.RecipientEmail,
                            address = selOrder.RecipientAddressCity + selOrder.RecipientAddressDistinct + selOrder.RecipientAddressDetail
                        },
                        details = new OrderDetailDetailsDto
                        {
                            quantity = selOrder.Quantity ?? -99999,
                            productName = selOrder.ProductName,
                            productDes = selOrder.ProductDesc,
                            //productImgSrc = (ServerPath.Domain) + selOrder.ImgSrc,
                            productImgSrc = selOrder.ImgSrc,
                            productImgAlt = selOrder.ProductName,
                            rent = selOrder.Rent ?? -99999,
                            deposit = selOrder.Deposit ?? -99999,
                            fee = selOrder.fee ?? -99999,
                            //feeDeposit = selOrder.fee ??-99999 + selOrder.Deposit ?? -99999,  //前端計算
                            finalAmount = selOrder.FinalAmount ?? -99999,
                            period = selOrder.Period,
                            rentDate = selOrder.RentDate ?? DateTime.MinValue,
                            rentStamp = (selOrder.RentDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                            returnDate = selOrder.ReturnDate ?? DateTime.MinValue,
                            returnStamp = (selOrder.ReturnDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                            payment = selOrder.PaymentBy
                        }

                    };



                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "成功取得會員訂單",
                        data = selData
                    };

                    return Ok(result);
                }
                else
                {
                    //沒找到cart

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無指定訂單"
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
        /// 店家取得會員訂單(全部)
        /// 'api/v1/members/orders'
        /// 帶入JWT 驗證
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [JwtAuthFilter]
        [Route("api/v1/admin/orders")]
        public IHttpActionResult OrdersAdminAll()
        {
            //if (!ModelState.IsValid)
            //{
            //    var errorStr = new
            //    {
            //        statusCode = 400,
            //        status = false,
            //        message = "新增訂單失敗"
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

                var selOrders = db.Orders.Where(o => o.IsDeleted == false);

                var selData = selOrders.ToList().Select(o => new OrdersAdminDto
                {
                    orderId = o.OrderId,
                    memberName = o.GetCartId.GetUserId.UserName ?? "",
                    orderStatus = o.OrderStatus ?? "",
                    shippingStatus = o.ShippingStatus ?? "",
                    orderCode = o.OrderCode ?? "",
                    createdDate = o.CreateAt != null ? o.CreateAt : DateTime.MinValue,
                    createdStamp = o.CreateAt.ToString("yyyy-MM-dd") ?? "",
                    shipping = o.shipping ?? "",

                    quantity = o.Quantity ?? -99999,
                    finalAmount = o.FinalAmount ?? -99999,
                    rentDate = o.RentDate ?? DateTime.MinValue,
                    rentStamp = (o.RentDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                    returnDate = o.ReturnDate ?? DateTime.MinValue,
                    returnStamp = (o.ReturnDate ?? DateTime.MinValue).ToString("yyyy-MM-dd")
                });



                var result = new
                {
                    statusCode = 200,
                    status = true,
                    message = "成功取得會員訂單",
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


        /// <summary>
        /// 店家編輯訂單狀態 
        /// 'api/v1/admin/order'
        /// 帶入JWT 驗證
        /// </summary>
        /// <returns></returns>
        [HttpPut]
        [JwtAuthFilter]
        [Route("api/v1/admin/order")]
        public IHttpActionResult OrderUpdataAdminAll([FromBody] OrderUpdateAdminDto request)
        {
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "編輯訂單狀態失敗"
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

                //找到指定訂單並實體化
                var selOrders = db.Orders.Where(o => o.IsDeleted == false).Where(o => o.OrderId == request.orderId).FirstOrDefault();

                if (selOrders != null)
                {

                    selOrders.OrderStatus = request.orderStatus;
                    selOrders.ShippingStatus = request.shippingStatus;

                    selOrders.UpdateAt = DateTime.Now;

                    db.SaveChanges();

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "成功編輯訂單狀態",
                    };

                    return Ok(result);
                }
                else
                {

                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "無指定訂單",
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
        /// 查詢訂單細節(管理者)
        /// 'api/admin/order/{orderId}'
        /// 帶入JWT 驗證(店家)
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [JwtAuthFilter]
        [Route("api/admin/order/{orderId}")]
        public IHttpActionResult OrdersDetailAdmin(int orderId)
        {
            //if (!ModelState.IsValid)
            //{
            //    var errorStr = new
            //    {
            //        statusCode = 400,
            //        status = false,
            //        message = "新增訂單失敗"
            //    };

            //    return Ok(errorStr);
            //}

            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            try
            {

                int userId = Convert.ToInt32(userToken["UserId"].ToString());

                int selOrderId = orderId;

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

                var selOrders = db.Orders.Where(o => o.IsDeleted == false);

                if (selOrders.Any(o => o.OrderId == selOrderId))
                {
                    var selOrder = selOrders.Where(o => o.OrderId == selOrderId).FirstOrDefault();

                    var selData = new
                    {
                        orderStatus = selOrder.OrderStatus ?? "",
                        shippingStatus = selOrder.ShippingStatus ?? "",
                        orderCode = selOrder.OrderCode ?? "",
                        createdDate = selOrder.CreateAt != null ? selOrder.CreateAt : DateTime.MinValue,
                        createdStamp = selOrder.CreateAt.ToString("yyyy-MM-dd") ?? "",
                        note = selOrder.note ?? "",
                        shipping = selOrder.shipping ?? "",
                        shippinginfo = new
                        {
                            name = selOrder.RecipientName,
                            phone = selOrder.RecipientPhone,
                            email = selOrder.RecipientEmail,
                            address = selOrder.RecipientAddressCity + selOrder.RecipientAddressDistinct + selOrder.RecipientAddressDetail,
                            addressZIP = selOrder.RecipientAddressZIP,
                            addressCity = selOrder.RecipientAddressCity,
                            addressDistrict = selOrder.RecipientAddressDistinct,
                            AddressDetail = selOrder.RecipientAddressDetail,

                        },
                        details = new OrderDetailDetailsDto
                        {
                            quantity = selOrder.Quantity ?? -99999,
                            productName = selOrder.ProductName,
                            productDes = selOrder.ProductDesc,
                            //productImgSrc = (ServerPath.Domain) + selOrder.ImgSrc,
                            productImgSrc = selOrder.ImgSrc,
                            productImgAlt = selOrder.ProductName,
                            rent = selOrder.Rent ?? -99999,
                            deposit = selOrder.Deposit ?? -99999,
                            fee = selOrder.fee ?? -99999,
                            //feeDeposit = selOrder.fee ??-99999 + selOrder.Deposit ?? -99999,  //前端計算
                            finalAmount = selOrder.FinalAmount ?? -99999,
                            period = selOrder.Period,
                            rentDate = selOrder.RentDate ?? DateTime.MinValue,
                            rentStamp = (selOrder.RentDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                            returnDate = selOrder.ReturnDate ?? DateTime.MinValue,
                            returnStamp = (selOrder.ReturnDate ?? DateTime.MinValue).ToString("yyyy-MM-dd"),
                            payment = selOrder.PaymentBy
                        },
                        member = new
                        {
                            memberId = selOrder.GetCartId.GetUserId.UserId,
                            name = selOrder.GetCartId.GetUserId.UserName ?? "",
                            email = selOrder.GetCartId.GetUserId.UserEmail ?? "",
                            lineId = selOrder.GetCartId.GetUserId.LineId ?? "",
                            phone = selOrder.GetCartId.GetUserId.UserInfos.Where(uf => uf.IsDeleted == false && uf.UserId == selOrder.GetCartId.GetUserId.UserId).FirstOrDefault()?.UserPhone ?? "",
                        }
                    };

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "成功取得指定會員訂單細節",
                        data = selData
                    };
                    return Ok(result);
                }
                else
                {
                    var result = new
                    {
                        statusCode = 404,
                        status = true,
                        message = "無指定訂單",
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
        /// 編輯訂單訊息(管理者後台)
        /// 'api/admin/order/{orderId}'
        /// 帶入JWT 驗證(店家)
        /// </summary>
        /// <returns></returns>
        [HttpPut]
        [JwtAuthFilter]
        [Route("api/admin/order/{orderId}")]
        public IHttpActionResult OrdersDetailUpdateAdmin(int orderId,[FromBody] OrderDetailUpdateAdminDto request)
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

                int selOrderId = orderId;

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

                var selOrders = db.Orders.Where(o => o.IsDeleted == false).Where(o => o.OrderId == selOrderId && o.GetCartId.UserId == request.memberId);

                if (selOrders.Any())
                {
                    var selOrder = selOrders.FirstOrDefault();

                    selOrder.OrderStatus = request.orderStatus;
                    selOrder.shipping = request.shipping;
                    selOrder.ShippingStatus=request.shippingStatus;
                    selOrder.RecipientName=request.shippingInfo.name;
                    selOrder.RecipientPhone=request.shippingInfo.phone;
                    selOrder.RecipientEmail=request.shippingInfo.email;
                    selOrder.RecipientAddressZIP = request.shippingInfo.addressZip;
                    selOrder.RecipientAddressCity=request.shippingInfo.addressCity;
                    selOrder.RecipientAddressDistinct =request.shippingInfo.addressDistrict;
                    selOrder.RecipientAddressDetail=request.shippingInfo.addressDetail;
                    selOrder.Quantity =request.details.quantity;
                    selOrder.ProductName = request.details.productName;
                    selOrder.Rent=request.details.rent;
                    selOrder.Deposit=request.details.deposit;
                    selOrder.fee=request.details.fee;
                    selOrder.FinalAmount=request.details.finalAmount;
                    selOrder.RentDate = request.details.rentStamp;
                    selOrder.ReturnDate = request.details.returnStamp;
                    selOrder.PaymentBy = request.details.payment;

                    db.SaveChanges();

                    var result = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "成功修改指定會員訂單細節",
                    };
                    return Ok(result);
                }
                else
                {
                    var result = new
                    {
                        statusCode = 404,
                        status = true,
                        message = "無指定訂單",
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


        //// GET: api/Orders
        //public IQueryable<Order> GetOrders()
        //{
        //    return db.Orders;
        //}

        //// GET: api/Orders/5
        //[ResponseType(typeof(Order))]
        //public IHttpActionResult GetOrder(int id)
        //{
        //    Order order = db.Orders.Find(id);
        //    if (order == null)
        //    {
        //        return NotFound();
        //    }

        //    return Ok(order);
        //}

        //// PUT: api/Orders/5
        //[ResponseType(typeof(void))]
        //public IHttpActionResult PutOrder(int id, Order order)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    if (id != order.OrderId)
        //    {
        //        return BadRequest();
        //    }

        //    db.Entry(order).State = EntityState.Modified;

        //    try
        //    {
        //        db.SaveChanges();
        //    }
        //    catch (DbUpdateConcurrencyException)
        //    {
        //        if (!OrderExists(id))
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

        //// POST: api/Orders
        //[ResponseType(typeof(Order))]
        //public IHttpActionResult PostOrder(Order order)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    db.Orders.Add(order);
        //    db.SaveChanges();

        //    return CreatedAtRoute("DefaultApi", new { id = order.OrderId }, order);
        //}

        //// DELETE: api/Orders/5
        //[ResponseType(typeof(Order))]
        //public IHttpActionResult DeleteOrder(int id)
        //{
        //    Order order = db.Orders.Find(id);
        //    if (order == null)
        //    {
        //        return NotFound();
        //    }

        //    db.Orders.Remove(order);
        //    db.SaveChanges();

        //    return Ok(order);
        //}

        //protected override void Dispose(bool disposing)
        //{
        //    if (disposing)
        //    {
        //        db.Dispose();
        //    }
        //    base.Dispose(disposing);
        //}

        //private bool OrderExists(int id)
        //{
        //    return db.Orders.Count(e => e.OrderId == id) > 0;
        //}

        #endregion
    }
}