namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateUserTable_updateRequiredItem : DbMigration
    {
        public override void Up()
        {
            AlterColumn("dbo.Users", "JWTtoken", c => c.String());
            CreateIndex("dbo.Users", "UserEmail", unique: true);
        }
        
        public override void Down()
        {
            DropIndex("dbo.Users", new[] { "UserEmail" });
            AlterColumn("dbo.Users", "JWTtoken", c => c.String(nullable: false));
        }
    }
}
