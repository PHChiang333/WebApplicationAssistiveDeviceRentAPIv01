namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateUserAndUserInfo_updateItems01 : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.UserInfoes", "UserPhone", c => c.String());
            DropColumn("dbo.Users", "UserPhone");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Users", "UserPhone", c => c.String());
            DropColumn("dbo.UserInfoes", "UserPhone");
        }
    }
}
