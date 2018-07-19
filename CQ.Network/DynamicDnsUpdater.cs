using CQ.Crypto;
using Newtonsoft.Json;
using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using X4D.Diagnostics.Logging;

namespace CQ.Network
{
    public sealed class DynamicDnsUpdater
    {
        private readonly Crypt _crypt;

        private readonly Action<string> _onStatusChange;

        public DynamicDnsUpdater(Crypt crypt, Action<string> onStatusChange)
        {
            _crypt = crypt;
            _onStatusChange = onStatusChange;
        }

        public async Task UpdateDynamicDnsAsync()
        {
            try
            {
                var hostname = System.Configuration.ConfigurationManager.AppSettings["no-ip:hostname"];
                var auth = System.Configuration.ConfigurationManager.AppSettings["no-ip:auth"];
                var keyid = System.Configuration.ConfigurationManager.AppSettings["no-ip:key"] ?? "chat";
                if (!string.IsNullOrEmpty(hostname) && !string.IsNullOrEmpty(auth))
                {
                    var key = _crypt.LoadKeypair(keyid, false);
                    var edata = Convert.FromBase64String(auth);
                    var data = key.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                    var parts = Encoding.UTF8.GetString(data).Split(':');

                    var userName = parts[0];
                    var password = parts[1];

                    var ipaddr = System.Configuration.ConfigurationManager.AppSettings["no-ip:address"] ?? WhatsMyIP();

                    var ddnsSuccess = true;
                    var ddnsResult = "";
                    try
                    {
                        var webClient = new WebClient
                        {
                            Credentials = new NetworkCredential(userName, password),
                            CachePolicy = new System.Net.Cache.RequestCachePolicy(System.Net.Cache.RequestCacheLevel.NoCacheNoStore),
                            Encoding = Encoding.UTF8
                        };
                        webClient.Headers.Add("User-Agent", "shenc/0.1 shenc@mrshaunwilson.com");
                        ddnsResult = await webClient.DownloadStringTaskAsync(
                            new Uri($"https://dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={ipaddr}"));
                    }
                    catch (Exception ex)
                    {
                        // TODO: use a logging framework, instead
                        ddnsSuccess = false;
                        ddnsResult = (new StringBuilder($"Exception: {ex.GetType().FullName}"))
                            .AppendLine($"Exception: {ex.GetType().FullName}")
                            .AppendLine($"Message: {ex.Message}")
                            .AppendLine($"StackTrace: {ex.StackTrace}")
                            .ToString();
                    }
                    _onStatusChange($"DDNS RESULT: {(ddnsSuccess ? "SUCCESS" : "FAILED")}> {ddnsResult}"
                        .Log(ddnsSuccess
                            ? System.Diagnostics.TraceEventType.Information
                            : System.Diagnostics.TraceEventType.Warning));
                }
            }
            catch (Exception ex)
            {
                ex.Log();
            }
        }

        private string WhatsMyIP()
        {
            var uri = @"https://ipapi.co/json/"; // TODO: make configurable
            var webClient = new WebClient();
            webClient.Headers.Add("User-Agent", "shenc/0.1 shenc@mrshaunwilson.com");
            var response = webClient.DownloadString(uri);
            dynamic obj = JsonConvert.DeserializeObject(response);
            return (obj != null && !string.IsNullOrWhiteSpace(Convert.ToString(obj.ip)))
                ? obj.ip
                : Dns.GetHostEntry(IPAddress.Any).AddressList.FirstOrDefault();
        }

    }
}
