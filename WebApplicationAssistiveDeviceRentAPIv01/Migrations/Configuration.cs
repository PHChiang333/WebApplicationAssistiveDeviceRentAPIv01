namespace WebApplicationAssistiveDeviceRentAPIv01.Migrations
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Migrations;
    using System.Linq;

    internal sealed class Configuration : DbMigrationsConfiguration<WebApplicationAssistiveDeviceRentAPIv01.Models.DBModel>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = false;
            ContextKey = "WebApplicationAssistiveDeviceRentAPIv01.Models.DBModel";
        }

        protected override void Seed(WebApplicationAssistiveDeviceRentAPIv01.Models.DBModel context)
        {
            //  This method will be called after migrating to the latest version.

            //  You can use the DbSet<T>.AddOrUpdate() helper extension method
            //  to avoid creating duplicate seed data.
        }
    }
}
