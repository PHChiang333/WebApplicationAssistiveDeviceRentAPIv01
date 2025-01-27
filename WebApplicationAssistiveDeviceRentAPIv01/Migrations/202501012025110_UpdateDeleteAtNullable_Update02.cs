namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateDeleteAtNullable_Update02 : DbMigration
    {
        public override void Up()
        {
            AlterColumn("dbo.ProductBodyParts", "DeleteAt", c => c.DateTime());
            AlterColumn("dbo.ProductTypes", "DeleteAt", c => c.DateTime());
            AlterColumn("dbo.ProductFeatures", "DeleteAt", c => c.DateTime());
            AlterColumn("dbo.ProductGMFMLvs", "DeleteAt", c => c.DateTime());
            AlterColumn("dbo.ProductImgs", "DeleteAt", c => c.DateTime());
            AlterColumn("dbo.ProductInfoes", "DeleteAt", c => c.DateTime());
            AlterColumn("dbo.Users", "DeleteAt", c => c.DateTime());
            AlterColumn("dbo.UserInfoes", "DeleteAt", c => c.DateTime());
        }
        
        public override void Down()
        {
            AlterColumn("dbo.UserInfoes", "DeleteAt", c => c.DateTime(nullable: false));
            AlterColumn("dbo.Users", "DeleteAt", c => c.DateTime(nullable: false));
            AlterColumn("dbo.ProductInfoes", "DeleteAt", c => c.DateTime(nullable: false));
            AlterColumn("dbo.ProductImgs", "DeleteAt", c => c.DateTime(nullable: false));
            AlterColumn("dbo.ProductGMFMLvs", "DeleteAt", c => c.DateTime(nullable: false));
            AlterColumn("dbo.ProductFeatures", "DeleteAt", c => c.DateTime(nullable: false));
            AlterColumn("dbo.ProductTypes", "DeleteAt", c => c.DateTime(nullable: false));
            AlterColumn("dbo.ProductBodyParts", "DeleteAt", c => c.DateTime(nullable: false));
        }
    }
}
