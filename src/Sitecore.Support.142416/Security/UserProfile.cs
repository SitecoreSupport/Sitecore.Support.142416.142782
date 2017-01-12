namespace Sitecore.Support.Security
{
    using System;
    using System.Reflection;
    using Sitecore.Caching.UserProfile;
    using Sitecore.Configuration;
    using Sitecore.Diagnostics;
    using Sitecore.StringExtensions;

    public class UserProfile : Sitecore.Security.UserProfile
    {
        private static readonly MethodInfo IsUserVirtualMethodInfo;
        private static readonly MethodInfo GetPropertyValueFromProfileItemMethodInfo;
        private static readonly MethodInfo CacheGetterMethodInfo;

        static UserProfile()
        {
            IsUserVirtualMethodInfo = typeof(Sitecore.Security.UserProfile).GetMethod("IsUserVirtual", BindingFlags.Instance | BindingFlags.NonPublic);
            GetPropertyValueFromProfileItemMethodInfo = typeof(Sitecore.Security.UserProfile).GetMethod("GetPropertyValueFromProfileItem", BindingFlags.Instance | BindingFlags.NonPublic);
            CacheGetterMethodInfo = typeof(Sitecore.Security.UserProfile).GetProperty("Cache", BindingFlags.Instance | BindingFlags.NonPublic).GetGetMethod(true);
        }

        /// <summary>
        /// Gets a named property value.
        /// </summary>
        /// <param name="propertyName">
        /// Name of the property.
        /// </param>
        /// <returns>
        /// The value.
        /// </returns>
        [CanBeNull]
        protected override object GetPropertyValueCore([NotNull] string propertyName)
        {
            Assert.ArgumentNotNullOrEmpty(propertyName, "propertyName");

            UserProfileCacheRecord cacheValue = ((UserProfileCache)CacheGetterMethodInfo.Invoke(this, new object[0])).GetRecord(this.UserName, propertyName);
            if (cacheValue != null)
            {
                return cacheValue.Value;
            }

            object value;

            try
            {
                if (IsUserVirtualMethodInfo != null && (bool)IsUserVirtualMethodInfo.Invoke(this, new object[0]))
                {
                    value = this.ProfileUser.RuntimeSettings.Properties.ContainsKey(propertyName) ? this.ProfileUser.RuntimeSettings.Properties[propertyName] : null;
                }
                else
                {
                    value = Factory.GetRetryer().Execute(() => this.GetPropertyValue(propertyName));
                }
            }
            catch
            {
                value = null;
            }

            if ((value == null || (value is string && value.ToString() == string.Empty)) &&
              !propertyName.Equals("ProfileItemId", StringComparison.OrdinalIgnoreCase))
            {
                value = (string)GetPropertyValueFromProfileItemMethodInfo.Invoke(this, new object[] { propertyName });
            }

            ((UserProfileCache)CacheGetterMethodInfo.Invoke(this, new object[0])).AddRecord(this.UserName, propertyName, value);

            return value;
        }

        /// <summary>
        /// Gets or sets a value indicating whether this user is an administrator.
        /// </summary>
        /// <value>
        /// <c>true</c> if this user is an administrator; otherwise, <c>false</c>.
        /// </value>
        public override bool IsAdministrator
        {
            get
            {
                object value = this.GetPropertyValueCore("IsAdministrator");

                if (value == null)
                {
                    return false;
                }

                if (value is string)
                {
                    bool result;
                    return bool.TryParse(value.ToString(), out result) ? result : false;
                }

                try
                {
                    return (bool)value;
                }
                catch
                {
                    if (IsUserVirtualMethodInfo != null && (bool)IsUserVirtualMethodInfo.Invoke(this, new object[0]))
                    {
                        return this.ProfileUser != null && this.ProfileUser.RuntimeSettings.IsAdministrator;
                    }

                    Log.SingleWarn("Cannot get IsAdministrator property value from the profile for user '{0}'".FormatWith(this.UserName), this);
                    return false;
                }
            }

            set
            {
                this.SetPropertyValueCore("IsAdministrator", value);
            }
        }
    }
}