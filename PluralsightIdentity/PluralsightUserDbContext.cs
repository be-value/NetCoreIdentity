using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace PluralsightIdentity
{
    public class PluralsightUserDbContext : IdentityDbContext<PluralsightUser>
    {
        public PluralsightUserDbContext(DbContextOptions<PluralsightUserDbContext> options) : base(options)
        {
             
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<PluralsightUser>(user => user.HasIndex(x => x.Locale).IsUnique(false));

            builder.Entity<Organization>(org =>
            {
                org.ToTable("Organizations");
                org.HasKey(x => x.Id);
                org.HasMany<PluralsightUser>().WithOne().HasForeignKey(x => x.OrgId).IsRequired(false);
            });
        }
    }
}
