namespace Sitecore.Support.Security
{
    using System.Reflection;
    using Sitecore.Diagnostics;
    using Sitecore.StringExtensions;

    public class UserProfile : Sitecore.Security.UserProfile
    {
        private static readonly MethodInfo IsUserVirtualMethodInfo;

        static UserProfile()
        {
            IsUserVirtualMethodInfo = typeof(Sitecore.Security.UserProfile).GetMethod("IsUserVirtual", BindingFlags.Instance | BindingFlags.NonPublic);
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