using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace RSA_ASP.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return RedirectToAction("UploadFile");
        }
        [HttpGet]
        public ActionResult UploadFile()
        {
            return View();
        }
        [HttpPost]
        public ActionResult GenerateRSA()
        {
            AsymmetricCipherKeyPair newkeys = RSASigner.GetKeyPairWithDotNet();
            this.Session["keys"] = newkeys;
            ViewBag.pubkey = RSASigner.FormatToPEM(newkeys.Public);
            ViewBag.privkey = RSASigner.FormatToPEM(newkeys.Private);
            return View("UploadFile");
        }
        public ActionResult SignFile(HttpPostedFileBase file,String[] RSAPriv,string [] RSAPub)
        {
                if (file != null && file.ContentLength > 0)
                {
                    MemoryStream target = new MemoryStream();
                    file.InputStream.CopyTo(target);
                    byte[] data = target.ToArray();
                    ViewBag.rsasig=RSASigner.Sign(data,RSAPriv);
                    ViewBag.Message = "Podpisano!";
                    return View("UploadFile");
            }
                ViewBag.Message="Błąd wysyłania pliku.";
                return View("UploadFile");

        }
        public ActionResult VerifySignature(HttpPostedFileBase file, String[] RSAPriv, string[] RSAPub, string [] Sign)
        {
            if (file.ContentLength > 0)
            {
                MemoryStream target = new MemoryStream();
                file.InputStream.CopyTo(target);
                byte[] data = target.ToArray();
                RsaKeyParameters pubk;
                using (var stringReader = new StringReader(string.Join("\n", RSAPub)))
                {
                    var pemReader = new PemReader(stringReader);
                    var pemObject = pemReader.ReadObject(); // null!
                    pubk = (RsaKeyParameters)pemObject;
                }
                try
                {
                    if (RSASigner.VerifySignedHash(data, Convert.FromBase64String(string.Join("\n", Sign)), pubk))
                        ViewBag.Message = "Zgadza się!";
                    else ViewBag.Message = "Błąd weryfikacji";
                    return View("UploadFile");
                }
                catch
                {
                    ViewBag.Message = "Błędny podpis/klucz";
                    return View("UploadFile");
                }
            }
            ViewBag.Message = "Błąd wysyłania pliku.";
            return View("UploadFile");
        }
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}