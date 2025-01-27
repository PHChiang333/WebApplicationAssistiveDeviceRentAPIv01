namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateUserTable_AddRegexNUniqueLimit : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "UserEmail", c => c.String(nullable: false, maxLength: 254));
            AlterColumn("dbo.Users", "UserName", c => c.String(maxLength: 100));
            AlterColumn("dbo.Users", "UserPassword", c => c.String(nullable: false, maxLength: 64));
        }
        
        public override void Down()
        {
            AlterColumn("dbo.Users", "UserPassword", c => c.String(nullable: false, maxLength: 100));
            AlterColumn("dbo.Users", "UserName", c => c.String(nullable: false, maxLength: 100));
            DropColumn("dbo.Users", "UserEmail");
        }
    }
}
