﻿using System.ComponentModel.DataAnnotations;

namespace PluralsightIdentity.Models
{
    public class LoginModel
    {
        public string UserName { get; set; }

        [DataType(DataType.Password)]
        public string Password { get; set; }

        public string ReturnUrl { get; set; }
    }
}