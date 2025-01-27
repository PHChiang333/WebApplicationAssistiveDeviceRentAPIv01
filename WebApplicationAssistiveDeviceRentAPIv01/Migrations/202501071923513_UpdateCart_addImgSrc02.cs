namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateCart_addImgSrc02 : DbMigration
    {
        public override void Up()
        {
            AlterColumn("dbo.Carts", "ImgSrc", c => c.String());
        }
        
        public override void Down()
        {
            AlterColumn("dbo.Carts", "ImgSrc", c => c.String(nullable: false));
        }
    }
}
