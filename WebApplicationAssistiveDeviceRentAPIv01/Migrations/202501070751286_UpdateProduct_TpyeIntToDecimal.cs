namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateProduct_TpyeIntToDecimal : DbMigration
    {
        public override void Up()
        {
            AlterColumn("dbo.Products", "Rent", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            AlterColumn("dbo.Products", "Deposite", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            AlterColumn("dbo.Products", "Fee", c => c.Decimal(nullable: false, precision: 18, scale: 2));
        }
        
        public override void Down()
        {
            AlterColumn("dbo.Products", "Fee", c => c.Int(nullable: false));
            AlterColumn("dbo.Products", "Deposite", c => c.Int(nullable: false));
            AlterColumn("dbo.Products", "Rent", c => c.Int(nullable: false));
        }
    }
}
