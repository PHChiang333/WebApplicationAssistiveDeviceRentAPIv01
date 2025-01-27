namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddCart_CreateCartTable : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.Carts",
                c => new
                    {
                        CartId = c.Int(nullable: false, identity: true),
                        UserId = c.Int(nullable: false),
                        ProductId = c.Int(nullable: false),
                        ProductName = c.String(nullable: false),
                        ProductDesc = c.String(),
                        Rent = c.Decimal(nullable: false, precision: 18, scale: 2),
                        Deposite = c.Decimal(nullable: false, precision: 18, scale: 2),
                        quantity = c.Int(nullable: false),
                        Amount = c.Decimal(nullable: false, precision: 18, scale: 2),
                        period = c.Int(nullable: false),
                        rentDate = c.DateTime(nullable: false),
                        returnDate = c.DateTime(nullable: false),
                        isTurnedOrder = c.Boolean(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(),
                    })
                .PrimaryKey(t => t.CartId)
                .ForeignKey("dbo.Products", t => t.ProductId, cascadeDelete: true)
                .ForeignKey("dbo.Users", t => t.UserId, cascadeDelete: true)
                .Index(t => t.UserId)
                .Index(t => t.ProductId);
            
        }
        
        public override void Down()
        {
            DropForeignKey("dbo.Carts", "UserId", "dbo.Users");
            DropForeignKey("dbo.Carts", "ProductId", "dbo.Products");
            DropIndex("dbo.Carts", new[] { "ProductId" });
            DropIndex("dbo.Carts", new[] { "UserId" });
            DropTable("dbo.Carts");
        }
    }
}
