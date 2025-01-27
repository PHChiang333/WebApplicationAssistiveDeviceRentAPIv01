using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Util;
using WebApplicationAssistiveDeviceRentAPIv01.Class;
using WebApplicationAssistiveDeviceRentAPIv01.Models;
using WebApplicationAssistiveDeviceRentAPIv01.Models.Dto.LinePay;

namespace WebApplicationAssistiveDeviceRentAPIv01.Controllers
{
    public class LinePayController : ApiController
    {
        private readonly LinePayService _linePayService = new LinePayService();

        private DBModel db = new DBModel();


        // 交易請求的API
        [HttpPost]
        [Route("api/v1/linePay/reserve")]
        public async Task<IHttpActionResult> OrderReserve(LinePayRequestDto request)
        {
            try
            {
                var resultLinePayReserve = await _linePayService.ReservePaymentAsync(request);


                if (resultLinePayReserve.returnCode == "0000")
                {
                    string transactionId = resultLinePayReserve.info.transactionId.ToString();
                    var result = new
                    {
                        statusCode = 200,
                        Status = true,
                        data = new
                        {
                            transactionId = transactionId,
                            PaymentUrl = new
                            {
                                web = resultLinePayReserve.info.paymentUrl.web,
                                app = resultLinePayReserve.info.paymentUrl.app,
                            }
                        }
                    };

                    return Ok(result);

                }
                else
                {
                    var result = new
                    {
                        statusCode = 400,
                        Status = false,
                    };

                    return Ok(result);
                }

            }
            catch (Exception ex)
            {
                return Ok(ex);
            }
        }

        // 確認交易的API
        [HttpPost]
        [Route("api/v0/linePay/confirm")]
        public async Task<IHttpActionResult> OrderConfirmTest(long transactionId, int amount)
        {
            try
            {
                var confirmRequest = new ConfirmRequestDto
                {
                    transactionId = transactionId,
                    amount = amount   //這邊要帶入實際的finalAmount
                };
                var result = await _linePayService.GetPaymentStatusAsync(confirmRequest);

                try
                {
                    //var selOrder = db.Orders.Where(o => o.)
                }
                catch (Exception ex)
                {

                }


                return Ok(result);
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        // 確認交易的API
        [HttpPost]
        [Route("api/v1/linePay/confirm")]
        public async Task<IHttpActionResult> OrderConfirm([FromBody] ConfirmRequestFromFrontendDto request)
        {

            // 模型驗證
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "錯誤的請求"
                };

                return Ok(errorStr);
            }


            try
            {
                var selTransactionId = request.transactionId;
                var selOrderId = request.orderId;

                var selOrder = db.Orders.Where(o => o.IsDeleted == false).Where(o => o.TransactionId == selTransactionId.ToString() && o.OrderId == selOrderId).FirstOrDefault();


                if (selOrder != null)
                {

                    try
                    {
                        var confirmRequest = new ConfirmRequestDto
                        {
                            transactionId = selTransactionId,
                            amount = (int)selOrder.FinalAmount,   //這邊要帶入finalAmount
                        };

                        //打LinePay confirm API
                        var resultLinePayConfirm = await _linePayService.GetPaymentStatusAsync(confirmRequest);

                        //確認結果
                        if (resultLinePayConfirm.returnCode == "0000")
                        {
                            //確認成功 "0000"

                            selOrder.OrderStatus = "已付款";
                            db.SaveChanges();

                            var result = new
                            {
                                statusCode = 200,
                                status = true,
                                message = "LinePay訂單確認成功",
                            };
                            return Ok(result);
                        }

                        else
                        {
                            //失敗，訂單確認異常

                            var result = new
                            {
                                statusCode = 400,
                                status = false,
                                message = "LinePay訂單確認失敗",
                                linePayReturnCode = resultLinePayConfirm.returnCode,
                            };
                            return Ok(result);

                        }
                    }
                    catch (Exception ex)
                    {
                        var result = new
                        {
                            statusCode = 400,
                            status = false,
                            message = "向LinePay comfirm失敗",
                        };
                        return Ok(result);
                    }

                }
                else
                {
                    var result = new
                    {
                        statusCode = 404,
                        status = false,
                        message = "DB查無此訂單",
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













    }
}
