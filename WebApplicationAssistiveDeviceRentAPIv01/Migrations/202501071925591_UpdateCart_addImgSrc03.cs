namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateCart_addImgSrc03 : DbMigration
    {
        public override void Up()
        {
            AlterColumn("dbo.Carts", "ProductName", c => c.String());
            AlterColumn("dbo.Carts", "Rent", c => c.Decimal(precision: 18, scale: 2));
            AlterColumn("dbo.Carts", "Deposit", c => c.Decimal(precision: 18, scale: 2));
            AlterColumn("dbo.Carts", "Quantity", c => c.Int());
            AlterColumn("dbo.Carts", "Amount", c => c.Decimal(precision: 18, scale: 2));
            AlterColumn("dbo.Carts", "Period", c => c.Int());
            AlterColumn("dbo.Carts", "RentDate", c => c.DateTime());
            AlterColumn("dbo.Carts", "ReturnDate", c => c.DateTime());
            AlterColumn("dbo.Carts", "IsTurnedOrder", c => c.Boolean());
        }
        
        public override void Down()
        {
            AlterColumn("dbo.Carts", "IsTurnedOrder", c => c.Boolean(nullable: false));
            AlterColumn("dbo.Carts", "ReturnDate", c => c.DateTime(nullable: false));
            AlterColumn("dbo.Carts", "RentDate", c => c.DateTime(nullable: false));
            AlterColumn("dbo.Carts", "Period", c => c.Int(nullable: false));
            AlterColumn("dbo.Carts", "Amount", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            AlterColumn("dbo.Carts", "Quantity", c => c.Int(nullable: false));
            AlterColumn("dbo.Carts", "Deposit", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            AlterColumn("dbo.Carts", "Rent", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            AlterColumn("dbo.Carts", "ProductName", c => c.String(nullable: false));
        }
    }
}
