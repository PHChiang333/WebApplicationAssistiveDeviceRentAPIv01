namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateOrder_AddLinePaytransactionId : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Orders", "TransactionId", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.Orders", "TransactionId");
        }
    }
}
