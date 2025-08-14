using System;
using System.Text;
using System.Text.RegularExpressions;

namespace Netigent.Utils.Ldap.Extensions
{
    public static class ObjectExtensions
    {
        public static string ToBinaryString(this Guid guid)
        {
            var bytes = guid.ToByteArray();
            var sb = new StringBuilder();
            foreach (var b in bytes)
            {
                sb.AppendFormat("\\{0:X2}", b);
            }
            return sb.ToString();
        }

        public static string GetPlainUsername(this string username)
        {
            // Determine the username
            return username.Contains("@") // If account has a @ e.g. john.bloggs@mycompany.com
                    ? username.Split('@')[0] // Take 1st part as possible username
                    : username.Contains("\\") // If user is presented as mycompany\john.bloggs
                        ? username.Split('\\')[1] // Take last part
                        : username; // Otherwise treat username as-is e.g. john.bloggs
        }

        public static bool IsValidPassword(this string password, int minLength = 8, int groupComplexity = 3)
        {
            if (string.IsNullOrEmpty(password))
                return false;

            // Must have at least 8 characters
            if (password.Length < minLength)
                return false;

            int groupsMet = 0;

            if (Regex.IsMatch(password, "[A-Z]")) groupsMet++; // Uppercase
            if (Regex.IsMatch(password, "[a-z]")) groupsMet++; // Lowercase
            if (Regex.IsMatch(password, "[0-9]")) groupsMet++; // Digit
            if (Regex.IsMatch(password, @"[!@#$%^&*(),.?""{}|<>_\-\\/\[\];:'`~+=]")) groupsMet++; // Special

            return groupsMet >= groupComplexity;
        }
    }
}
