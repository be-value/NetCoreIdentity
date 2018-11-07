using System.ComponentModel.DataAnnotations;

namespace PluralsightIdentity.Models
{
    public class TwoFactorModel
    {
        [Required]
        public string Token { get; set; }
    }
}