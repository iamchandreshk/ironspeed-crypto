using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IronSpeedCrypto
{
    public class Crypto
    {
        private byte[] bytIV;
        private SymmetricAlgorithm _CryptoService;

        public Crypto()
        {
            this.bytIV = ApplicationSettings.Current.DefaultEncryptionKey;
            this._CryptoService = new RijndaelManaged();
        }

        private byte[] GetLegalKey(string Key)
        {
            string s;
            if (this._CryptoService.LegalKeySizes.Length > 0)
            {
                int maxSize = this._CryptoService.LegalKeySizes[0].MaxSize;
                int num = checked((int)Math.Round(unchecked((double)maxSize / 8.0)));
                if (checked(Key.Length * 8) > maxSize)
                {
                    s = Key.Substring(0, num);
                }
                else
                {
                    int minSize = this._CryptoService.LegalKeySizes[0].MinSize;
                    while (checked(Key.Length * 8) > minSize)
                        checked { minSize += this._CryptoService.LegalKeySizes[0].SkipSize; }
                    s = Key.PadRight(num, "X"[0]);
                }
            }
            else
                s = Key;
            if (this._CryptoService.LegalBlockSizes.Length > 0)
            {
                int blockSize = this._CryptoService.BlockSize;
                int num = checked((int)Math.Round(unchecked((double)blockSize / 8.0)));
                this.bytIV = (byte[])CopyArray(this.bytIV, new byte[checked(s.Length - 1 + 1)]);
                if (checked(s.Length * 8) > blockSize)
                    this.bytIV = (byte[])CopyArray(this.bytIV, new byte[checked(num - 1 + 1)]);
            }
            return Encoding.ASCII.GetBytes(s);
        }

        private byte[] CopyArray(byte[] source, byte[] destination)
        {
            for (int i = 0; i < destination.Length; i++)
            {
                destination[i] = source[i];
            }
            return destination;
        }


        public virtual string Encrypt(string Source)
        {
            return this.Encrypt(Source, this.GetCryptoKeyWithoutSessionVariable(), Encoding.ASCII);
        }

        public string Encrypt(string Source, string Key, Encoding Encoding)
        {
            if (Source == null || Source.Trim().Length == 0)
                return Source;

            byte[] buffer = Encoding.ASCII.GetBytes(Source);

            MemoryStream memoryStream = new MemoryStream();
            this._CryptoService.Key = this.GetLegalKey(Key);
            this._CryptoService.IV = this.bytIV;
            ICryptoTransform encryptor = this._CryptoService.CreateEncryptor();
            CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write);
            cryptoStream.Write(buffer, 0, buffer.Length);
            cryptoStream.FlushFinalBlock();
            cryptoStream.Close();
            byte[] array = memoryStream.ToArray();
            memoryStream.Close();
            return Convert.ToBase64String(array);
        }

        public virtual string Decrypt(string Source)
        {
            return this.Decrypt(Source, this.GetCryptoKeyWithoutSessionVariable(), Encoding.ASCII);
        }

        public virtual string Decrypt(string Source, string Key, Encoding Encoding)
        {
            if (Source == null || Source.Trim().Length == 0)
                return Source;
            try
            {
                byte[] buffer;
                MemoryStream memoryStream1;
                buffer = Convert.FromBase64String(Source);
                memoryStream1 = new MemoryStream(buffer);
                byte[] legalKey = this.GetLegalKey(Key);
                this._CryptoService.Key = legalKey;
                this._CryptoService.IV = this.bytIV;
                ICryptoTransform decryptor1 = this._CryptoService.CreateDecryptor();
                CryptoStream cryptoStream1 = new CryptoStream((Stream)memoryStream1, decryptor1, CryptoStreamMode.Read);
                string str = "";
                StreamReader streamReader = string.Compare(Encoding.EncodingName, Encoding.ASCII.EncodingName, false) != 0 ? (string.Compare(Encoding.EncodingName, Encoding.Unicode.EncodingName, false) != 0 ? new StreamReader((Stream)cryptoStream1, Encoding.GetEncoding(CultureInfo.CurrentUICulture.TextInfo.ANSICodePage)) : new StreamReader((Stream)cryptoStream1, Encoding.GetEncoding(CultureInfo.CurrentUICulture.TextInfo.ANSICodePage))) : new StreamReader((Stream)cryptoStream1, Encoding.GetEncoding(CultureInfo.CurrentUICulture.TextInfo.ANSICodePage));
                str = streamReader.ReadToEnd();
                streamReader.Close();
                memoryStream1.Close();
                cryptoStream1.Close();
                return str;
            }
            catch { }
            return Source;
        }


        private string GetCryptoKeyWithoutSessionVariable()
        {
            return "ffx4yp{B3015A1E-7845-1245-B014-42D3082634E8}xehl45";
        }

        public enum Providers
        {
            DES,
            RC2,
            Rijndael,
            TripelDES,
        }
    }
}
