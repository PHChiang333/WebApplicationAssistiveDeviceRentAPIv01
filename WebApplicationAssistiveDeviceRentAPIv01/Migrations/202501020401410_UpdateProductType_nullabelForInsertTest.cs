namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateProductType_nullabelForInsertTest : DbMigration
    {
        public override void Up()
        {
            AlterColumn("dbo.ProductTypes", "CreateAt", c => c.DateTime());
            AlterColumn("dbo.ProductTypes", "UpdateAt", c => c.DateTime());
            AlterColumn("dbo.ProductTypes", "IsDeleted", c => c.Boolean());
        }
        
        public override void Down()
        {
            AlterColumn("dbo.ProductTypes", "IsDeleted", c => c.Boolean(nullable: false));
            AlterColumn("dbo.ProductTypes", "UpdateAt", c => c.DateTime(nullable: false));
            AlterColumn("dbo.ProductTypes", "CreateAt", c => c.DateTime(nullable: false));
        }
    }
}
