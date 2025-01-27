using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Xml;

namespace WebApplicationAssistiveDeviceRentAPIv01.Models
{
    public class DBModel : DbContext
    {
        // 您的內容已設定為使用應用程式組態檔 (App.config 或 Web.config)
        // 中的 'DBModel' 連接字串。根據預設，這個連接字串的目標是
        // 您的 LocalDb 執行個體上的 'WebApplicationAssistiveDeviceRentAPIv01.Models.DBModel' 資料庫。
        // 
        // 如果您的目標是其他資料庫和 (或) 提供者，請修改
        // 應用程式組態檔中的 'DBModel' 連接字串。
        public DBModel()
            : base("name=DBModel")
        {
        }

        internal IEnumerable<int> WHERE(Func<object, bool> value)
        {
            throw new NotImplementedException();
        }

        // 針對您要包含在模型中的每種實體類型新增 DbSet。如需有關設定和使用
        // Code First 模型的詳細資訊，請參閱 http://go.microsoft.com/fwlink/?LinkId=390109。

        // public virtual DbSet<MyEntity> MyEntities { get; set; }


        public virtual DbSet<User> User { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // 配置 UserEmail 為唯一
            modelBuilder.Entity<User>()
                .HasIndex(u => u.UserEmail)
                .IsUnique();

            // 配置欄位長度
            modelBuilder.Entity<User>()
                .Property(u => u.UserEmail)
                .HasMaxLength(254);

            modelBuilder.Entity<User>()
                .Property(u => u.UserPassword)
                .HasMaxLength(64);
        }

        public virtual DbSet<UserInfo> UserInfo { get; set; }

        public virtual DbSet<Product> Products { get; set; }

        public virtual DbSet<ProductType> ProductTypes { get; set; }

        public virtual DbSet<ProductImg> ProductImgs { get; set; }

        public virtual DbSet<ProductFeature> ProductFeatures { get; set; }

        public virtual DbSet<ProductInfo> ProductInfos { get; set; }


        public virtual DbSet<ProductGMFMLv> ProductGMFMLvs { get; set; }

        public virtual DbSet<ProductBodyPart> ProductBodyParts { get; set; }


        public virtual DbSet<Cart> Carts { get; set; }

        public virtual DbSet<Order> Orders { get; set; }

        public virtual DbSet<Inquiry> Inquirys { get; set; }
        public virtual DbSet<InquiryProduct> InquiryProducts { get; set; }
        public virtual DbSet<Suggest> Suggests { get; set; }
        public virtual DbSet<SuggestProduct> SuggestProducts { get; set; }


    }

    //public class MyEntity
    //{
    //    public int Id { get; set; }
    //    public string Name { get; set; }
    //}









}



