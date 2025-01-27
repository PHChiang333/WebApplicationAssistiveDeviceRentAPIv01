namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateProduct_imgs : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.ProductImgs", "IsPreview", c => c.Boolean(nullable: false));
        }
        
        public override void Down()
        {
            DropColumn("dbo.ProductImgs", "IsPreview");
        }
    }
}
