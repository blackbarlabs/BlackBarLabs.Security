using System;
using System.Collections.Generic;

namespace BlackBarLabs.Security
{
    public sealed class SecurityCheckpoint
    {
        private readonly IList<SecurityCheck> checks = new List<SecurityCheck>();

        private SecurityCheckpoint()
        {

        }

        public static SecurityCheckpoint Initialize()
        {
            return new SecurityCheckpoint();
        }

        public SecurityCheckpoint Check(SecurityCheck check)
        {
            if(check==null)
                throw new ArgumentNullException("check");
            checks.Add(check);
            return this;
        }

        public void Check()
        {
            return;
            //TODO: Add this back in once Security is fully integrated.
            //if (checks.Any(check => !check.AllowAccess()))
            //    throw new SecurityException();
        }
    }
}
