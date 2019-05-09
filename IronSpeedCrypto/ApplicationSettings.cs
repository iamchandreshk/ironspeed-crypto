using System.Collections.Generic;

namespace IronSpeedCrypto
{
    public class ApplicationSettings
    {
        #region Declaration of ApplicationSettings
        private static ApplicationSettings _Current = new ApplicationSettings();
        public static ApplicationSettings Current
        {
            get
            {
                return ApplicationSettings._Current;
            }
        }
        #endregion

        #region Declaration of URLEncryptionKey
        private string _URLEncryptionKey;
        public string URLEncryptionKey
        {
            get
            {
                this._URLEncryptionKey = this.GetAppSetting("ApplicationName");
                return this._URLEncryptionKey;
            }
            set
            {
                this._URLEncryptionKey = value;
            }
        }
        #endregion

        #region Declaration of DefaultEncryptionKey
        private byte[] _DefaultEncryptionKey;
        public byte[] DefaultEncryptionKey
        {
            get
            {
                this.GetDefaultEncryptionKey();
                return this._DefaultEncryptionKey;
            }
            set
            {
                this._DefaultEncryptionKey = value;
            }
        }
        #endregion


        private ApplicationSettings()
        {
            this.GetDefaultEncryptionKey();
            this._URLEncryptionKey = this.GetAppSetting("{B3015A1E-B8D2-4606-B014-42D3082634E8}"); // URLEncryptionKey
        }

        public void GetDefaultEncryptionKey()
        {
            string appSetting = this.GetAppSetting("78, 90, 23, 7, 54, 109, 34, 231, 90, 66, 109, 185, 228, 143, 89, 77, 190, 89, 103, 148, 54, 4, 98, 67, 243, 162, 68, 201, 73, 59, 184, 52"); // DefaultEncryptionKey
            if (appSetting == null || string.IsNullOrEmpty(appSetting))
                return;
            List<byte> byteList = new List<byte>();
            string[] strArray = appSetting.Split(',');
            int index = 0;
            while (index < strArray.Length)
            {
                byte result;
                if (byte.TryParse(strArray[index], out result))
                    byteList.Add(result);
                checked { ++index; }
            }
            this._DefaultEncryptionKey = byteList.ToArray();
        }

        public string GetAppSetting(string key)
        {
            return key;
            //return ConfigurationManager.AppSettings[key];
        }
    }
}
