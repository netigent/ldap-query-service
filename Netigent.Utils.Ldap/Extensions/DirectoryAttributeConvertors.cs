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
				if(da != null)
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
				return (T)Convert.ChangeType(new Guid(byteSID), typeof(T));

			else if (typeof(T) == typeof(SecurityIdentifier))
#pragma warning disable CA1416 // Validate platform compatibility
				return (T)Convert.ChangeType(new SecurityIdentifier(byteSID, 0), typeof(T));
#pragma warning restore CA1416 // Validate platform compatibility


			else if (typeof(T) == typeof(DateTime))
			{
				//"20210519121843.0Z"
				//"yyyyMMddHHmmssZ"
				var datestring = Encoding.UTF8.GetString(byteSID);
				DateTime time = DateTime.ParseExact(datestring.Split(".",StringSplitOptions.None)[0], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None);
				return (T)Convert.ChangeType(time, typeof(T));
			}

			return default;

		}
	}
}
