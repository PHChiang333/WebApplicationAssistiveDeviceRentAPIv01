using Namotion.Reflection;
using System;
using System.Collections.Generic;
using System.Data.Entity.Migrations.Sql;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Http;
//using System.Web.Mvc;
using WebApplicationAssistiveDeviceRentAPIv01.Class;
using WebApplicationAssistiveDeviceRentAPIv01.Models;
using WebApplicationAssistiveDeviceRentAPIv01.Models.Dto;
using WebApplicationAssistiveDeviceRentAPIv01.Security;

namespace WebApplicationAssistiveDeviceRentAPIv01.Controllers
{
    public class AuthController : ApiController
    {
        //實體化DB
        private DBModel db = new DBModel();

        /// <summary>
        /// 驗證登入狀態
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        //驗證登入
        // Post api/auth
        [HttpPost]
        [Route("api/v1/auth")]
        [JwtAuthFilter]
        //public IHttpActionResult Auth([FromBody] authRequest request)
        public IHttpActionResult Auth()
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


            // 取出請求內容，解密 JwtToken 取出資料
            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            JwtAuthUtil jwtAuthUtil = new JwtAuthUtil();
            // ExpRefreshToken() 生成刷新效期 JwtToken 用法
            string jwtToken = jwtAuthUtil.ExpRefreshToken(userToken);
            // 處理完請求內容後，順便送出刷新效期的 JwtToken

            //----------測試用-------------------------------------------------------------------------------
            //測試用
            //string testToken = jwtAuthUtil.ExpRefreshToken2(userToken);   //exp.ADD(-60)

            //string selId = userToken["UserId"].ToString();
            //string exp = userToken["Exp"].ToString();
            //var newToken = JwtAuthUtil.GetPayload(jwtToken);
            //string newExp = newToken["Exp"].ToString();
            //----------測試用-------------------------------------------------------------------------------

            var responseStr = new
            {
                statusCode = 200,
                status = true,
                message = "用戶已登入",
                data = new
                {
                    jwtToken = jwtToken,
                }

                //----------測試用-------------------------------------------------------------------------------
                //usertoken = userToken,
                //userId = userId,
                //CurrentToken = Request.Headers.Authorization.Parameter,
                //TestExpiredToken = testToken
                //----------測試用-------------------------------------------------------------------------------
            };

            return Ok(responseStr);

        }



        /// <summary>
        /// 註冊
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        //POST api/v1/auth/sign_up
        [HttpPost]
        [Route("api/v1/auth/sign_up")]
        public IHttpActionResult Register([FromBody] requestRegister request)
        {

            // 模型驗證
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "註冊失敗"
                };

                return Ok(errorStr);
            }

            // 邊界情況檢查
            if (request.Email.Length > 254)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "註冊失敗 Email cannot exceed 254 characters."
                };

                return Ok(errorStr);
            }

            var emailParts = request.Email.Split('@');

            if (emailParts[0].Length > 64)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "註冊失敗 Local part of email cannot exceed 64 characters."
                };

                return Ok(errorStr);
            }

            string emailRegex = @"^(?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*|""(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*"")@(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?|\[(?:IPv6:[a-fA-F0-9:.]+|[0-9]{1,3}(?:\.[0-9]{1,3}){3})\])$";
            if (!Regex.IsMatch(request.Email, emailRegex))
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "註冊失敗 Invalid email format."
                };

                return Ok(errorStr);
            }




            if (request.Password.Length > 64 || request.Password.Length < 8)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "註冊失敗 Password must be between 8 and 64 characters."
                };

                return Ok(errorStr);
            }

            string passwordRegex = @"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?"":{}|<>])[A-Za-z\d!@#$%^&*(),.?"":{}|<>]{8,}$";
            if (!Regex.IsMatch(request.Password, passwordRegex))
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "註冊失敗 Invalid password format."
                };

                return Ok(errorStr);
            }



            //傳入
            string vailName = request.Name;
            //string vailPhone = request.Phone;
            string vailEmail = request.Email;
            string vailPw = request.Password;

            //實體化User table 
            User user = new User();

            //var existingUser = db.User.Where(u => u.IsDeleted == false).SingleOrDefault(u => u.UserEmail == vailEmail);  //改用Any()

            var existingUser = db.User.Where(u => u.IsDeleted == false).Any(u => u.UserEmail == vailEmail);

            string msg = string.Empty;

            //有驗證資料
            if (existingUser)
            {
                //TODO 補充LINE登入註冊的驗證邏輯  (已有LineId的帳號轉為更新)
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "註冊失敗 Email is already in use."
                };

                return Ok(errorStr);
            }
            else
            {
                //無User資料
                //註冊
                //新增User
                user.UserName = vailName;
                //user.UserPhone = vailPhone;
                user.UserEmail = vailEmail;
                user.UserPassword = vailPw;
                user.IsAdmin = false;

                user.CreateAt = DateTime.Now;
                user.UpdateAt = DateTime.Now;
                user.IsDeleted = false;
                user.DeleteAt = null;

                db.User.Add(user);
                db.SaveChanges();


                //新增UserInfo


                var selNewUser = db.User.Where(u => u.UserEmail == vailEmail).FirstOrDefault();

                int selNewUserId = selNewUser.UserId;

                UserInfo userInfoAdd = new UserInfo();

                userInfoAdd.UserId = selNewUserId;

                userInfoAdd.Gender = "";
                userInfoAdd.Birth = DateTime.Now;
                userInfoAdd.UserPhone = "";
                userInfoAdd.AllowedContactPeriod = "全天 09：00 - 21：00";
                userInfoAdd.AddressZIP = "";
                userInfoAdd.AddressCity = "";
                userInfoAdd.AddressDistinct = "";
                userInfoAdd.AddressDetail = "";

                userInfoAdd.CreateAt = DateTime.Now;
                userInfoAdd.UpdateAt = DateTime.Now;
                userInfoAdd.IsDeleted = false;
                userInfoAdd.DeleteAt = null;


                db.UserInfo.Add(userInfoAdd);
                db.SaveChanges();

                msg = "註冊成功！";

                return Ok(new
                {
                    statusCode = 200,
                    status = true,
                    message = "註冊成功！",


                });
            }



        }


        /// <summary>
        /// 登入
        /// (測試用)Email:googlexxx@gmail.com
        /// (測試用)Password:frankC123!
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        //POST api/v1/auth/sign_in
        [HttpPost]
        [Route("api/v1/auth/sign_in")]
        public IHttpActionResult SignIn([FromBody] requestLogin request)
        {

            // 模型驗證
            if (!ModelState.IsValid)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "登入失敗"
                };

                return Ok(errorStr);
            }

            // 邊界情況檢查
            if (request.Email.Length > 254)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "登入失敗 Email cannot exceed 254 characters."
                };

                return Ok(errorStr);
            }

            var emailParts = request.Email.Split('@');

            if (emailParts[0].Length > 64)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "登入失敗 Local part of email cannot exceed 64 characters."
                };

                return Ok(errorStr);
            }

            string emailRegex = @"^(?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*|""(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*"")@(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?|\[(?:IPv6:[a-fA-F0-9:.]+|[0-9]{1,3}(?:\.[0-9]{1,3}){3})\])$";
            if (!Regex.IsMatch(request.Email, emailRegex))
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "登入失敗 Invalid email format."
                };

                return Ok(errorStr);
            }




            if (request.Password.Length > 64 || request.Password.Length < 8)
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "登入失敗 Password must be between 8 and 64 characters."
                };

                return Ok(errorStr);
            }

            string passwordRegex = @"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?"":{}|<>])[A-Za-z\d!@#$%^&*(),.?"":{}|<>]{8,}$";
            if (!Regex.IsMatch(request.Password, passwordRegex))
            {
                var errorStr = new
                {
                    statusCode = 400,
                    status = false,
                    message = "登入失敗 Invalid password format."
                };

                return Ok(errorStr);
            }



            //傳入
            string vailEmail = request.Email;
            string vailPw = request.Password;

            //實體化User table 
            User user = new User();



            var isExisted = db.User.Where(u => u.IsDeleted == false).Any(u => u.UserEmail == vailEmail);

            string msg = string.Empty;

            //有驗證資料
            if (isExisted)
            {
                var existingUser = db.User.Where(u => u.IsDeleted == false).SingleOrDefault(u => u.UserEmail == vailEmail);

                var existingUserInfo = db.UserInfo.Where(ui => ui.IsDeleted == false).SingleOrDefault(ui => ui.UserId == existingUser.UserId);

                if (vailEmail == existingUser.UserEmail && vailPw == existingUser.UserPassword)
                {
                    //生成JWTtoken
                    JwtAuthUtil jwtAuthUtil = new JwtAuthUtil();
                    string jwtToken = jwtAuthUtil.GenerateToken(existingUser.UserId);

                    var selData = new
                    {
                        jwtToken = jwtToken,
                        name = existingUser.UserName,
                        email = existingUser.UserEmail,
                        phone = existingUserInfo.UserPhone,
                        addressZip = existingUserInfo.AddressZIP,
                        addressCity = existingUserInfo.AddressCity,
                        addressDistinct = existingUserInfo.AddressDistinct,
                        addressDetail = existingUserInfo.AddressDetail,
                        IsAdmin = existingUser.IsAdmin,
                    };

                    var responseStr = new
                    {
                        statusCode = 200,
                        status = true,
                        message = "登入成功！",
                        //jwtToken = jwtToken,
                        data = selData

                    };

                    return Ok(responseStr);
                }
                else
                {
                    var errorStr = new
                    {
                        statusCode = 403,
                        status = false,
                        message = "登入失敗 Check Email and password",
                    };

                    return Ok(errorStr);
                }
            }
            else
            {
                //無User資料
                var errorStr = new
                {
                    statusCode = 404,
                    status = false,
                    message = "登入失敗 Account not found.",
                };

                return Ok(errorStr);
            }
        }





        /// <summary>
        /// 驗證登入狀態後登出
        /// jwtToekn為過期token
        /// api/v1/auth/sign_out
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("api/v1/auth/sign_out")]
        [JwtAuthFilter]
        public IHttpActionResult SignOut()
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


            // 取出請求內容，解密 JwtToken 取出資料
            var userToken = JwtAuthUtil.GetPayload(Request.Headers.Authorization.Parameter);

            JwtAuthUtil jwtAuthUtil = new JwtAuthUtil();
            // RevokeToken()生成錯誤secretKey和過期exp JwtToken 用法
            string jwtToken = jwtAuthUtil.RevokeToken();
            // 處理完請求內容後，順便送出刷新效期的 JwtToken

            var responseStr = new
            {
                statusCode = 200,
                status = true,
                message = "用戶已登出",
                data = new
                {
                    jwtToken = jwtToken,
                }
            };

            return Ok(responseStr);


        }







    }




}

