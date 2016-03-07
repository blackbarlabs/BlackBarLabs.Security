namespace BlackBarLabs.Security
{
    public abstract class SecurityClearance
    {
        public abstract void IssueClearance();

        public abstract void RevokeClearance();
    }
}
