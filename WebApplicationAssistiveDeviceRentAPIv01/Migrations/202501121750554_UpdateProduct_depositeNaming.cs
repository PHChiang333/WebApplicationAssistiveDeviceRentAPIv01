namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateProduct_depositeNaming : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Products", "Deposit", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            DropColumn("dbo.Products", "Deposite");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Products", "Deposite", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            DropColumn("dbo.Products", "Deposit");
        }
    }
}
