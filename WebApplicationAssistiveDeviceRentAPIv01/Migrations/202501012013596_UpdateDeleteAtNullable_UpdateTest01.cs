namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateDeleteAtNullable_UpdateTest01 : DbMigration
    {
        public override void Up()
        {
            AlterColumn("dbo.Products", "DeleteAt", c => c.DateTime());
        }
        
        public override void Down()
        {
            AlterColumn("dbo.Products", "DeleteAt", c => c.DateTime(nullable: false));
        }
    }
}
