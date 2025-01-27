namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateDeleteAtNullable : DbMigration
    {
        public override void Up()
        {
            DropForeignKey("dbo.Users", "User_UserId", "dbo.Users");
            DropIndex("dbo.Users", new[] { "User_UserId" });
            AlterColumn("dbo.ProductImgs", "ProductImgName", c => c.String());
            DropColumn("dbo.Users", "User_UserId");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Users", "User_UserId", c => c.Int());
            AlterColumn("dbo.ProductImgs", "ProductImgName", c => c.String(nullable: false));
            CreateIndex("dbo.Users", "User_UserId");
            AddForeignKey("dbo.Users", "User_UserId", "dbo.Users", "UserId");
        }
    }
}
