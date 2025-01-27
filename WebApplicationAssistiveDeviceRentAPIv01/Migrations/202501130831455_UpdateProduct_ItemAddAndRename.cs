namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateProduct_ItemAddAndRename : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Orders", "PaymentBy", c => c.String());
            AddColumn("dbo.Orders", "note", c => c.String());
            AddColumn("dbo.Orders", "EstimatedArrivalDate", c => c.String());
            AddColumn("dbo.Orders", "PickupVerificationCode", c => c.String());
            DropColumn("dbo.Orders", "PaymentByl");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Orders", "PaymentByl", c => c.String());
            DropColumn("dbo.Orders", "PickupVerificationCode");
            DropColumn("dbo.Orders", "EstimatedArrivalDate");
            DropColumn("dbo.Orders", "note");
            DropColumn("dbo.Orders", "PaymentBy");
        }
    }
}
