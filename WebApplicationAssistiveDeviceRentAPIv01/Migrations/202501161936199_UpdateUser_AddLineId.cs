namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateUser_AddLineId : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "LineId", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.Users", "LineId");
        }
    }
}
