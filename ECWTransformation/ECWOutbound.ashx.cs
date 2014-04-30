using System;
using System.Web;
using SiemensISRM;
using System.Configuration;

namespace ECWTransformation
{
    /// <summary>
    /// Summary description for Encryptdi
    /// </summary>
    public class ECWOutbound : IHttpHandler
    {

        public void ProcessRequest(HttpContext context)
        {
            context.Response.ContentType = "text/plain";
            context.Response.Write("Processing Request...");
            String args = Transformation(context.Request.QueryString.ToString());
            context.Response.Redirect(args); 
        }

        public bool IsReusable
        {
            get
            {
                return false;
            }
        }

        // Transformation function for ASP.NET ECW Interop
        // qa is the plaintext unparsed query string that is expected to be passed to the receiving application
        // key is the secret key value, which is converted to a 256bit SHA hash (to ensure a 256 bit encryption key for AES)
        private static string Transformation(string qs)
        {
            if (qs == "") return "error: no query string";

            string key = ConfigurationManager.AppSettings["ECWCipherKey"].ToString();

            if (key == "") return "error: no encryption key";

            if (ConfigurationManager.AppSettings["ECWOutboundTimestamp"].ToString().ToLower() == "true") { qs = qs + "&timestamp=" + SIBTime.TimeStamp(); }

            try
            {
                byte[] IV = SIBCrypto.GenerateAESIV();
                byte[] cipherText = SIBCrypto.EncryptAES(qs, SIBCrypto.HashSHA256(key), IV);
                byte[] md5 = SIBCrypto.HashMD5(SIBCrypto.Concat(cipherText, IV));
                return ConfigurationManager.AppSettings["ECWOutboundRedirectURL"].ToString() + "?args1=" + SIBCrypto.URLEncode(Convert.ToBase64String(cipherText)) + "&args2=" + SIBCrypto.URLEncode(Convert.ToBase64String(IV)) + "&args3=" + SIBCrypto.URLEncode(Convert.ToBase64String(md5));
            }
            catch
            {
                return "error: transformation failure.";
            }
        }
    }
}