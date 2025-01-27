namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddTables_All06 : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.InquiryProducts",
                c => new
                    {
                        InquiryProductId = c.Int(nullable: false, identity: true),
                        InquiryId = c.Int(nullable: false),
                        ProductId = c.Int(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(),
                    })
                .PrimaryKey(t => t.InquiryProductId)
                .ForeignKey("dbo.Inquiries", t => t.InquiryId, cascadeDelete: true)
                .ForeignKey("dbo.Products", t => t.ProductId, cascadeDelete: true)
                .Index(t => t.InquiryId)
                .Index(t => t.ProductId);
            
            CreateTable(
                "dbo.Inquiries",
                c => new
                    {
                        InquiryId = c.Int(nullable: false, identity: true),
                        InquiryCode = c.String(),
                        UserId = c.Int(nullable: false),
                        IsReplied = c.Boolean(),
                        GMFMLvCode = c.String(),
                        additionalInfo = c.String(),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(),
                    })
                .PrimaryKey(t => t.InquiryId)
                .ForeignKey("dbo.Users", t => t.UserId, cascadeDelete: true)
                .Index(t => t.UserId);
            
            CreateTable(
                "dbo.Suggests",
                c => new
                    {
                        SuggestId = c.Int(nullable: false, identity: true),
                        SuggestCode = c.String(),
                        InquiryId = c.Int(nullable: false),
                        GMFMLvCode = c.String(),
                        additionalInfo = c.String(),
                        IsSubmitted = c.Boolean(),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(),
                    })
                .PrimaryKey(t => t.SuggestId)
                .ForeignKey("dbo.Inquiries", t => t.InquiryId, cascadeDelete: true)
                .Index(t => t.InquiryId);
            
            CreateTable(
                "dbo.SuggestProducts",
                c => new
                    {
                        SuggestProductId = c.Int(nullable: false, identity: true),
                        SuggestId = c.Int(nullable: false),
                        ProductId = c.Int(nullable: false),
                        Reasons = c.String(),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(),
                    })
                .PrimaryKey(t => t.SuggestProductId)
                .ForeignKey("dbo.Products", t => t.ProductId, cascadeDelete: true)
                .ForeignKey("dbo.Suggests", t => t.SuggestId, cascadeDelete: true)
                .Index(t => t.SuggestId)
                .Index(t => t.ProductId);
            
            CreateTable(
                "dbo.Orders",
                c => new
                    {
                        OrderId = c.Int(nullable: false, identity: true),
                        OrderCode = c.String(),
                        CartId = c.Int(nullable: false),
                        ProductName = c.String(),
                        ProductDesc = c.String(),
                        Rent = c.Decimal(precision: 18, scale: 2),
                        Deposit = c.Decimal(precision: 18, scale: 2),
                        ImgSrc = c.String(),
                        shipping = c.String(),
                        fee = c.Decimal(precision: 18, scale: 2),
                        Quantity = c.Int(),
                        FinalAmount = c.Decimal(precision: 18, scale: 2),
                        Period = c.Int(nullable: false),
                        RentDate = c.DateTime(),
                        ReturnDate = c.DateTime(),
                        RecipientName = c.String(),
                        RecipientPhone = c.String(),
                        RecipientEmail = c.String(),
                        RecipientAddressZIP = c.String(),
                        RecipientAddressCity = c.String(),
                        RecipientAddressDistinct = c.String(),
                        RecipientAddressDetail = c.String(),
                        PaymentByl = c.String(),
                        PatmentStatus = c.String(),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(),
                    })
                .PrimaryKey(t => t.OrderId)
                .ForeignKey("dbo.Carts", t => t.CartId, cascadeDelete: true)
                .Index(t => t.CartId);
            
            AlterColumn("dbo.UserInfoes", "Birth", c => c.DateTime());
            AlterColumn("dbo.UserInfoes", "IsDisability", c => c.String());
            DropColumn("dbo.Carts", "ProductName");
            DropColumn("dbo.Carts", "ProductDesc");
            DropColumn("dbo.Carts", "Rent");
            DropColumn("dbo.Carts", "Deposit");
            DropColumn("dbo.Carts", "ImgSrc");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Carts", "ImgSrc", c => c.String());
            AddColumn("dbo.Carts", "Deposit", c => c.Decimal(precision: 18, scale: 2));
            AddColumn("dbo.Carts", "Rent", c => c.Decimal(precision: 18, scale: 2));
            AddColumn("dbo.Carts", "ProductDesc", c => c.String());
            AddColumn("dbo.Carts", "ProductName", c => c.String());
            DropForeignKey("dbo.Orders", "CartId", "dbo.Carts");
            DropForeignKey("dbo.InquiryProducts", "ProductId", "dbo.Products");
            DropForeignKey("dbo.SuggestProducts", "SuggestId", "dbo.Suggests");
            DropForeignKey("dbo.SuggestProducts", "ProductId", "dbo.Products");
            DropForeignKey("dbo.Suggests", "InquiryId", "dbo.Inquiries");
            DropForeignKey("dbo.InquiryProducts", "InquiryId", "dbo.Inquiries");
            DropForeignKey("dbo.Inquiries", "UserId", "dbo.Users");
            DropIndex("dbo.Orders", new[] { "CartId" });
            DropIndex("dbo.SuggestProducts", new[] { "ProductId" });
            DropIndex("dbo.SuggestProducts", new[] { "SuggestId" });
            DropIndex("dbo.Suggests", new[] { "InquiryId" });
            DropIndex("dbo.Inquiries", new[] { "UserId" });
            DropIndex("dbo.InquiryProducts", new[] { "ProductId" });
            DropIndex("dbo.InquiryProducts", new[] { "InquiryId" });
            AlterColumn("dbo.UserInfoes", "IsDisability", c => c.Boolean(nullable: false));
            AlterColumn("dbo.UserInfoes", "Birth", c => c.DateTime(nullable: false));
            DropTable("dbo.Orders");
            DropTable("dbo.SuggestProducts");
            DropTable("dbo.Suggests");
            DropTable("dbo.Inquiries");
            DropTable("dbo.InquiryProducts");
        }
    }
}
