namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddProductTables : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.ProductBodyParts",
                c => new
                    {
                        ProductBodyPartId = c.Int(nullable: false, identity: true),
                        ProductId = c.Int(nullable: false),
                        BodyPartCode = c.String(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.ProductBodyPartId)
                .ForeignKey("dbo.Products", t => t.ProductId, cascadeDelete: true)
                .Index(t => t.ProductId);
            
            CreateTable(
                "dbo.Products",
                c => new
                    {
                        ProductId = c.Int(nullable: false, identity: true),
                        ProductName = c.Int(nullable: false),
                        ProductTypeId = c.Int(nullable: false),
                        Rent = c.Int(nullable: false),
                        Deposite = c.Int(nullable: false),
                        Fee = c.Int(nullable: false),
                        ProductDesc = c.String(),
                        ProductManual = c.String(),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.ProductId)
                .ForeignKey("dbo.ProductTypes", t => t.ProductTypeId, cascadeDelete: true)
                .Index(t => t.ProductTypeId);
            
            CreateTable(
                "dbo.ProductTypes",
                c => new
                    {
                        ProductTypeId = c.Int(nullable: false, identity: true),
                        ProductTypeName = c.String(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.ProductTypeId);
            
            CreateTable(
                "dbo.ProductFeatures",
                c => new
                    {
                        ProductFeatureId = c.Int(nullable: false, identity: true),
                        ProductId = c.Int(nullable: false),
                        FeatureValue = c.String(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.ProductFeatureId)
                .ForeignKey("dbo.Products", t => t.ProductId, cascadeDelete: true)
                .Index(t => t.ProductId);
            
            CreateTable(
                "dbo.ProductInfoes",
                c => new
                    {
                        ProductInfoId = c.Int(nullable: false, identity: true),
                        ProductId = c.Int(nullable: false),
                        ProductInfoKey = c.String(nullable: false),
                        ProductInfoValue = c.String(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.ProductInfoId)
                .ForeignKey("dbo.Products", t => t.ProductId, cascadeDelete: true)
                .Index(t => t.ProductId);
            
            CreateTable(
                "dbo.ProductGMFMLvs",
                c => new
                    {
                        ProductGMFMLvId = c.Int(nullable: false, identity: true),
                        ProductId = c.Int(nullable: false),
                        GMFMLvCode = c.String(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.ProductGMFMLvId)
                .ForeignKey("dbo.Products", t => t.ProductId, cascadeDelete: true)
                .Index(t => t.ProductId);
            
            CreateTable(
                "dbo.ProductImgs",
                c => new
                    {
                        ProductImgId = c.Int(nullable: false, identity: true),
                        ProductId = c.Int(nullable: false),
                        ProductImgPath = c.String(nullable: false),
                        ProductImgName = c.String(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.ProductImgId)
                .ForeignKey("dbo.Products", t => t.ProductId, cascadeDelete: true)
                .Index(t => t.ProductId);
            
            CreateTable(
                "dbo.UserInfoes",
                c => new
                    {
                        UserInfoId = c.Int(nullable: false, identity: true),
                        UserId = c.Int(nullable: false),
                        Nickname = c.String(),
                        Gender = c.String(),
                        Birth = c.DateTime(nullable: false),
                        AllowedContactPeriod = c.String(),
                        AddressZIP = c.String(),
                        AddressCity = c.String(),
                        AddressDistinct = c.String(),
                        AddressDetail = c.String(),
                        IncomeLv = c.String(),
                        IsDisability = c.Boolean(nullable: false),
                        CreateAt = c.DateTime(nullable: false),
                        UpdateAt = c.DateTime(nullable: false),
                        IsDeleted = c.Boolean(nullable: false),
                        DeleteAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.UserInfoId)
                .ForeignKey("dbo.Users", t => t.UserId, cascadeDelete: true)
                .Index(t => t.UserId);
            
            AddColumn("dbo.Users", "UpdateAt", c => c.DateTime(nullable: false));
            AddColumn("dbo.Users", "DeleteAt", c => c.DateTime(nullable: false));
            AddColumn("dbo.Users", "User_UserId", c => c.Int());
            CreateIndex("dbo.Users", "User_UserId");
            AddForeignKey("dbo.Users", "User_UserId", "dbo.Users", "UserId");
        }
        
        public override void Down()
        {
            DropForeignKey("dbo.UserInfoes", "UserId", "dbo.Users");
            DropForeignKey("dbo.Users", "User_UserId", "dbo.Users");
            DropForeignKey("dbo.ProductImgs", "ProductId", "dbo.Products");
            DropForeignKey("dbo.ProductGMFMLvs", "ProductId", "dbo.Products");
            DropForeignKey("dbo.ProductBodyParts", "ProductId", "dbo.Products");
            DropForeignKey("dbo.ProductInfoes", "ProductId", "dbo.Products");
            DropForeignKey("dbo.ProductFeatures", "ProductId", "dbo.Products");
            DropForeignKey("dbo.Products", "ProductTypeId", "dbo.ProductTypes");
            DropIndex("dbo.UserInfoes", new[] { "UserId" });
            DropIndex("dbo.Users", new[] { "User_UserId" });
            DropIndex("dbo.ProductImgs", new[] { "ProductId" });
            DropIndex("dbo.ProductGMFMLvs", new[] { "ProductId" });
            DropIndex("dbo.ProductInfoes", new[] { "ProductId" });
            DropIndex("dbo.ProductFeatures", new[] { "ProductId" });
            DropIndex("dbo.Products", new[] { "ProductTypeId" });
            DropIndex("dbo.ProductBodyParts", new[] { "ProductId" });
            DropColumn("dbo.Users", "User_UserId");
            DropColumn("dbo.Users", "DeleteAt");
            DropColumn("dbo.Users", "UpdateAt");
            DropTable("dbo.UserInfoes");
            DropTable("dbo.ProductImgs");
            DropTable("dbo.ProductGMFMLvs");
            DropTable("dbo.ProductInfoes");
            DropTable("dbo.ProductFeatures");
            DropTable("dbo.ProductTypes");
            DropTable("dbo.Products");
            DropTable("dbo.ProductBodyParts");
        }
    }
}
