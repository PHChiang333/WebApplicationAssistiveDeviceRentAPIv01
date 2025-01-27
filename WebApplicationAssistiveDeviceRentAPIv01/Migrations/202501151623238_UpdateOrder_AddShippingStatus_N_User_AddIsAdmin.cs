namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateOrder_AddShippingStatus_N_User_AddIsAdmin : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "IsAdmin", c => c.Boolean(nullable: false));
            AddColumn("dbo.Orders", "OrderStatus", c => c.String());
            AddColumn("dbo.Orders", "ShippingStatus", c => c.String());
            DropColumn("dbo.Orders", "PatmentStatus");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Orders", "PatmentStatus", c => c.String());
            DropColumn("dbo.Orders", "ShippingStatus");
            DropColumn("dbo.Orders", "OrderStatus");
            DropColumn("dbo.Users", "IsAdmin");
        }
    }
}
