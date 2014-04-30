using System;
using System.Web;
using SiemensISRM;
using System.Configuration;
using System.Collections.Specialized;
using System.Linq;

namespace ECWTransformation
{
    /// <summary>
    /// Summary description for Decrypt
    /// </summary>
    public class ECWInbound : IHttpHandler
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
        // qs is the unparsed query string recieved from the calling application with the args1, args2, and args3 key/value pairs
        // key is the secret key value, which is converted to a 256bit SHA hash (to ensure a 256 bit encryption key for AES)
        private static string Transformation(string qs)
        {
            if (qs == "") return "error: no query string";

            string key = ConfigurationManager.AppSettings["ECWCipherKey"].ToString();

            if (key == "") return "error: no encryption key";

            try
            {
                NameValueCollection qsc = HttpUtility.ParseQueryString(qs);
                byte[] cipherText = Convert.FromBase64String(qsc.Get("args1"));
                byte[] IV = Convert.FromBase64String(qsc.Get("args2"));
                byte[] md5 = Convert.FromBase64String(qsc.Get("args3"));
                byte[] test = SIBCrypto.HashMD5(SIBCrypto.Concat(cipherText, IV));
                if (md5.SequenceEqual(test) != true) return "error: intregity check failed.";
                return ConfigurationManager.AppSettings["ECWInboundRedirectURL"].ToString() + "?" + SIBCrypto.DecryptAES(cipherText, SIBCrypto.HashSHA256(key), IV);
            }
            catch
            {
                return "error: transformation failure.";
            }
        }
    }
}