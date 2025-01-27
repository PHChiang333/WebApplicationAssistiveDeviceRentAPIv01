namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateCart_addImgSrc : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Carts", "Deposit", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            AddColumn("dbo.Carts", "ImgSrc", c => c.String(nullable: false));
            DropColumn("dbo.Carts", "Deposite");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Carts", "Deposite", c => c.Decimal(nullable: false, precision: 18, scale: 2));
            DropColumn("dbo.Carts", "ImgSrc");
            DropColumn("dbo.Carts", "Deposit");
        }
    }
}
