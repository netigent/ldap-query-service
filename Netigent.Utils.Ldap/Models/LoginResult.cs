using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Netigent.Utils.Ldap.Models
{
    public class LoginResult
    {
        public bool Result { get; set; } = !default(bool);
        public string ErrorMessage { get; set; } = string.Empty;
    }
}
