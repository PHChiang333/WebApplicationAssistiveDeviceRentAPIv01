﻿using Microsoft.Owin;
using NSwag.AspNet.Owin;
using Owin;
using System;
using System.Threading.Tasks;
using System.Web.Http;
using NSwag;
using NSwag.Generation.Processors.Security;





[assembly: OwinStartup(typeof(WebApplicationAssistiveDeviceRentAPIv01.Startup))]

namespace WebApplicationAssistiveDeviceRentAPIv01
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // 如需如何設定應用程式的詳細資訊，請瀏覽 https://go.microsoft.com/fwlink/?LinkID=316888
            var config = new HttpConfiguration();

            // 針對 JSON 資料使用 camel (JSON 回應會改 camel，但 Swagger 提示不會)
            //config.Formatters.JsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();

            app.UseSwaggerUi(typeof(Startup).Assembly, settings =>
            {
                // 針對 WebAPI，指定路由包含 Action 名稱
                //settings.GeneratorSettings.DefaultUrlTemplate =
                //    "api/{controller}/{action}/{id?}";


                // 加入客製化調整邏輯名稱版本等
                settings.PostProcess = document =>
                {
                    document.Info.Title = "WebAPI";
                };

                // 加入 Authorization JWT token 定義
                settings.GeneratorSettings.DocumentProcessors.Add(new SecurityDefinitionAppender("Bearer", new OpenApiSecurityScheme()
                {
                    Type = OpenApiSecuritySchemeType.ApiKey,
                    Name = "Authorization",
                    Description = "Type into the textbox: Bearer {your JWT token}.",
                    In = OpenApiSecurityApiKeyLocation.Header,
                    Scheme = "Bearer" // 不填寫會影響 Filter 判斷錯誤
                }));
                // REF: https://github.com/RicoSuter/NSwag/issues/1304 (每支 API 單獨呈現認證 UI 圖示)
                settings.GeneratorSettings.OperationProcessors.Add(new OperationSecurityScopeProcessor("Bearer"));
            });
            app.UseWebApi(config);
            config.MapHttpAttributeRoutes();
            config.EnsureInitialized();
        }
    }
}
