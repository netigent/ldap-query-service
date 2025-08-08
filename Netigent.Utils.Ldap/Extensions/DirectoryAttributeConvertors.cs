using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Security.Principal;
using System.Text;

namespace Netigent.Utils.Ldap.Extensions
{
    public static class DirectoryAttributeExtensions
    {
        public static List<T> ParseValues<T>(this DirectoryAttribute attributes)
        {
            if (attributes.Count == 0)
                return default;

            List<T> output = new List<T>();

            for (var i = 0; i < attributes.Count; i++)
            {
                DirectoryAttribute da = (attributes[i] as DirectoryAttribute);
                if (da != null)
                {
                    output.Add(da.ParseValue<T>());
                }
                else
                {
                    if (typeof(T) == typeof(String))
                        output.Add((T)Convert.ChangeType(attributes[i], typeof(String)));
                }

            }
            return output;
        }

        public static T ParseValue<T>(this DirectoryAttribute attribute)
        {
            if (attribute == null || attribute?.Count == 0)
                return default;

            byte[] byteSID = (byte[])attribute.GetValues(Type.GetType("System.Byte[]"))[0];

            if (byteSID == null)
                return default;

            if (typeof(T) == typeof(String))
                return (T)Convert.ChangeType(Encoding.UTF8.GetString(byteSID), typeof(T));

            else if (typeof(T) == typeof(Guid))
            {
                Guid outGuid;

                try
                {
                    outGuid = new Guid(byteSID);
                    return (T)Convert.ChangeType(outGuid, typeof(T));
                }
                catch (Exception)
                {
                    try
                    {
                        outGuid = new Guid(Encoding.UTF8.GetString(byteSID));
                        return (T)Convert.ChangeType(outGuid, typeof(T));
                    }
                    catch (Exception)
                    {
                        return default;
                    }
                }
            }

            else if (typeof(T) == typeof(SecurityIdentifier))
#pragma warning disable CA1416 // Validate platform compatibility
                return (T)Convert.ChangeType(new SecurityIdentifier(byteSID, 0), typeof(T));
#pragma warning restore CA1416 // Validate platform compatibility

            else if (typeof(T) == typeof(DateTime))
            {
                var datestring = Encoding.UTF8.GetString(byteSID);

                DateTime outTime;
                try
                {
                    //Ticks i.e. DateTime
                    //132816520909682406
                    //633896886277130000
                    long timeInterval = Convert.ToInt64(datestring);
                    outTime = new DateTime(timeInterval);
                    if (outTime.Year < 1000)
                    {
                        outTime = DateTime.FromFileTime(timeInterval);
                    }
                    return (T)Convert.ChangeType(outTime, typeof(T));
                }
                catch
                {
                    try
                    {
                        //Convertible timeStamps
                        //"20210519121843.0Z"
                        //"yyyyMMddHHmmssZ"
                        outTime = DateTime.ParseExact(datestring.Split('.')[0], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None);
                        return (T)Convert.ChangeType(outTime, typeof(T));
                    }
                    catch
                    {
                        return default;
                    }
                }
            }

            else if (typeof(T) == typeof(int))
                return (T)Convert.ChangeType(Encoding.UTF8.GetString(byteSID), typeof(T));

            else if (typeof(T) == typeof(long))
                return (T)Convert.ChangeType(Encoding.UTF8.GetString(byteSID), typeof(T));

            return default;

        }
    }
}
