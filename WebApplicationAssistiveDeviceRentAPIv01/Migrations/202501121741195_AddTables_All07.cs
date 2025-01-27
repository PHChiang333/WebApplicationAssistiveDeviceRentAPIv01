namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddTables_All07 : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Orders", "UserId", c => c.Int(nullable: false));
            AddColumn("dbo.Orders", "ProductId", c => c.Int(nullable: false));
        }
        
        public override void Down()
        {
            DropColumn("dbo.Orders", "ProductId");
            DropColumn("dbo.Orders", "UserId");
        }
    }
}
