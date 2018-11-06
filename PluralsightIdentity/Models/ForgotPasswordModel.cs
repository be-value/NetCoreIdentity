﻿using System.ComponentModel.DataAnnotations;

namespace PluralsightIdentity.Models
{
    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}