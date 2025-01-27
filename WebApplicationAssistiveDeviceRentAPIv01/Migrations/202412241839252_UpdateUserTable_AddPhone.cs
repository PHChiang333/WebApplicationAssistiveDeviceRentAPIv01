namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateUserTable_AddPhone : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "UserPhone", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.Users", "UserPhone");
        }
    }
}
