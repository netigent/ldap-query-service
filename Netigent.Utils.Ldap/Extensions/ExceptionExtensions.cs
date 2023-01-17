using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Netigent.Utils.Ldap.Extensions
{
    public static class ExceptionExtensions
    {
        public static bool IsLdapServerUnavailable(this Exception exception)
        {
            if(exception.InnerException != null)
            {
                return exception.InnerException.IsLdapServerUnavailable();
            }
            else
            {
                return exception.Message.ToLower().Contains("unavailable");
            }
        }
    }
}
