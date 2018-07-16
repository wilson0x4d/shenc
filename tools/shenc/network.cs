using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace shenc
{
    partial class Program
    {
        private static void OnClientAcceptCallback(ClientState client, RSA rsa)
        {
            var hostport = $"{client.HostName}:{client.PortNumber}";
            DebugLog($"{nameof(OnClientAcceptCallback)}({client},{GetThumbprint(rsa)}) via [{hostport}]");
            lock (_clients)
            {
                if (_clients.TryGetValue(hostport, out ClientState existingClient))
                {
                    if (client.Thumbprint == existingClient.Thumbprint || string.IsNullOrEmpty(existingClient.Thumbprint))
                    {
                        _clients[hostport] = client;
                        Log($"LISTEN: Replacing '{existingClient}' with '{client}'..");
#pragma warning disable 4014
                        StopClientWorker(existingClient);
#pragma warning restore 4014
                    }
                    else
                    {
                        Log($"LISTEN: Denying reconnction attempt for {hostport} because thumbprint '{client.Thumbprint}' does not match prior thumbprint '{existingClient.Thumbprint}'.");
                        return;
                    }
                }
                else
                {
                    _clients[hostport] = client;
                    Log($"LISTEN: Added '{client}'");
                }
            }
            client.Worker = StartClientWorker(client, rsa);
            client.Worker.ContinueWith((t) =>
            {
                lock (_clients)
                {
                    if (_clients.Remove(hostport))
                    {
                        DebugLog($"LISTEN: Removed {client}");
                    }
                }
            });
        }


        private static bool TryWebGet(
            Uri uri,
            string userName,
            string password,
            out string result)
        {
            try
            {
                var webClient = new WebClient
                {
                    Credentials = new NetworkCredential(userName, password),
                    CachePolicy = new System.Net.Cache.RequestCachePolicy(System.Net.Cache.RequestCacheLevel.NoCacheNoStore),
                    Encoding = Encoding.UTF8
                };
                webClient.Headers.Add("User-Agent", "shenc/0.1 shenc@mrshaunwilson.com");
                result = webClient.DownloadString(uri);
                return true;
            }
            catch (Exception ex)
            {
                // TODO: use a logging framework, instead
                result = (new StringBuilder($"Exception: {ex.GetType().FullName}"))
                    .AppendLine($"Exception: {ex.GetType().FullName}")
                    .AppendLine($"Message: {ex.Message}")
                    .AppendLine($"StackTrace: {ex.StackTrace}")
                    .ToString();
                return false;
            }
        }

        private static void UpdateDynamicDns()
        {
            try
            {
                var hostname = System.Configuration.ConfigurationManager.AppSettings["no-ip:hostname"];
                var auth = System.Configuration.ConfigurationManager.AppSettings["no-ip:auth"];
                var keyid = System.Configuration.ConfigurationManager.AppSettings["no-ip:key"] ?? "chat";
                if (!string.IsNullOrEmpty(hostname) && !string.IsNullOrEmpty(auth))
                {
                    var key = LoadKeypair(keyid, false);
                    var edata = Convert.FromBase64String(auth);
                    var data = key.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                    var parts = Encoding.UTF8.GetString(data).Split(':');

                    var userName = parts[0];
                    var password = parts[1];

                    var ipaddr = System.Configuration.ConfigurationManager.AppSettings["no-ip:address"] ?? WhatsMyIP();

                    var ddnsSuccess = TryWebGet(
                        new Uri($"https://dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={ipaddr}"),
                        userName,
                        password,
                        out string result);

                    Log($"=== DDNS RESULT: {(ddnsSuccess ? "SUCCESS" : "FAILED")}> {result}");
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
        }

        private static IDictionary<string, ClientState> _clients;
        private static TcpListener _listener;

        private static string WhatsMyIP()
        {
            var webClient = new WebClient();
            webClient.Headers.Add("User-Agent", "shenc/0.1 shenc@mrshaunwilson.com");
            var response = webClient.DownloadString("https://ipapi.co/json/");
            dynamic obj = JsonConvert.DeserializeObject(response);
            return (obj != null && !string.IsNullOrWhiteSpace(Convert.ToString(obj.ip)))
                ? obj.ip
                : Dns.GetHostEntry(IPAddress.Any).AddressList.FirstOrDefault();
        }

        private static async Task<ClientState> ConnectTo(string hostport, RSA rsa)
        {
            var parts = hostport.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            var hostName = parts[0];
            var portNumber = parts.Length > 1 ? int.Parse(parts[1]) : 18593;
            hostport = $"{hostName}:{portNumber}";
            var tcpClient = new TcpClient();
            tcpClient.NoDelay = true;
            Log($"Requesting connection to [{hostport}]..");
            await tcpClient.ConnectAsync(hostName, portNumber);
            var client = default(ClientState);
            lock (_clients)
            {
                client = new ClientState
                {
                    HostName = hostName,
                    PortNumber = portNumber,
                    TcpClient = tcpClient
                };
                if (_clients.TryGetValue(hostport, out ClientState existingClient))
                {
                    _clients[hostport] = client;
                    Log($"CONNECT: Replacing '{existingClient}' with '{client}'..");
#pragma warning disable 4014
                    StopClientWorker(existingClient);
#pragma warning restore 4014
                }
                else
                {
                    _clients[hostport] = client;
                    Log($"CONNECT: Added '{client}'");
                }
            }
#pragma warning disable 4014
            client.Worker = StartClientWorker(client, rsa);
            client.Worker.ContinueWith((t) =>
            {
                lock (_clients)
                {
                    if (_clients.Remove(hostport))
                    {
                        DebugLog($"LISTEN: Removed {client}");
                    }
                }
            });
#pragma warning restore 4014
            return client;
        }

        private static void Send(ClientState client, string message)
        {
            DebugLog($"{nameof(Send)}({client},{message})");
            var data = Encoding.UTF8.GetBytes(message);
            var edata = client.RSA == null ? data : client.RSA.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            client.TcpClient.Client.Send(BitConverter.GetBytes(edata.Length), SocketFlags.Partial);
            client.TcpClient.Client.Send(edata, SocketFlags.Partial);
        }
        private static async Task PING(ClientState client)
        {
            // TODO: ping should execute at regular intervals for keepalive and/or orphan/stale/dead link detection
            // TODO: ping should perform a "CHAL", ie. the PONG response should contain our signature, signed by the remote, which we can then use to authenticate the link. in a "man in the middle" attack should yield either a bad PING sig or a bad PONG sig which should result in a hard disconnect from either end
            await Task.CompletedTask; // in most cases, ping() is fire-and-forget. except during initial connection, we use ping/pong as an initial CHAL
        }

        private static async Task StartListening(
            CancellationTokenSource cancellationTokenSource,
            int port,
            Action<ClientState> onAcceptCallback)
        {
            if (_listener == null)
            {
                _listener = new TcpListener(IPAddress.Any, port);
                _listener.Start(10);
                Log($"LISTEN: Listening for connections on port '{port}'..");
                while (!cancellationTokenSource.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    client.NoDelay = true;
                    var remoteEndPoint = (client.Client.RemoteEndPoint as IPEndPoint);
                    DebugLog($"Connection request from [{remoteEndPoint.Address}:{remoteEndPoint.Port}]");
                    onAcceptCallback(new ClientState
                    {
                        HostName = $"{remoteEndPoint.Address}",
                        PortNumber = remoteEndPoint.Port,
                        TcpClient = client
                    });
                }
                _listener.Stop();
            }
        }

        private static void StopListening()
        {
            DebugLog($"{nameof(StopListening)}()");
            var listener = _listener;
            _listener = null;
            if (listener != null)
            {
                try
                {
                    listener.Stop();
                }
                catch (Exception ex)
                {
                    Log(ex);
                }
            }
            Log("NOLISTEN: Stopped listening.");
        }

        private static async Task StopClientWorker(ClientState client)
        {
            DebugLog($"{nameof(StopClientWorker)}({client})");
            try
            {
                var clientWorker = client.Worker;
                client.CancellationTokenSource.Cancel();
                if (clientWorker != null)
                {
                    await clientWorker;
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
        }
        private static async Task StartClientWorker(
    ClientState client,
    RSA rsa)
        {
            client.CancellationTokenSource = new CancellationTokenSource();

            // exchange our pubkey in the clear, this starts our conversation with remote
            var rsaParameters = rsa.ExportParameters(false);
            var pubkey = JsonConvert.SerializeObject(rsaParameters);
            Send(client, pubkey);

            var buf = new byte[1024 * 1024 * 48];
            var expectedSize = 0;
            var writeOffset = 0;
            var readOffset = 0;
            try
            {
                using (var stream = client.TcpClient.GetStream())
                {
                    var isSTUN = false;
                    while (!client.CancellationTokenSource.IsCancellationRequested)
                    {
                        if (expectedSize == 0)
                        {
                            var availableCount = (writeOffset - readOffset);
                            if (availableCount >= 4)
                            {
                                expectedSize = BitConverter.ToInt32(buf, readOffset);
                                if (expectedSize == 0)
                                {
                                    isSTUN = true;
                                    expectedSize = 4;
                                }
                                else
                                {
                                    isSTUN = false;
                                }
                                readOffset += 4;
                                if (expectedSize > (buf.Length - readOffset))
                                {
                                    throw new IndexOutOfRangeException($"Size Prefix '{expectedSize}' exceeds '{buf.Length}' for [{client.HostName}:{client.PortNumber}]");
                                }
                            }
                        }
                        else if ((writeOffset - readOffset) >= expectedSize)
                        {
                            var edata = new byte[expectedSize];
                            expectedSize = 0;
                            Array.Copy(buf, readOffset, edata, 0, edata.Length);
                            readOffset += edata.Length;
                            if (client.RSA == null)
                            {
                                // expect to receive pubkey from remote in the clear
                                var clientRSA = RSA.Create();
                                clientRSA.ImportParameters(
                                    JsonConvert.DeserializeObject<RSAParameters>(
                                        Encoding.UTF8.GetString(edata)));
                                client.RSA = clientRSA; // late assignment avoids race condition (invalid thumbprint result) from interstitial before import completes.
                                // check client pubkey thumbprint against whitelist, if not in whitelist then force a disconnect
                                lock (_whitelist)
                                {
                                    if (_whitelist.TryGetValue(client.Thumbprint, out string alias))
                                    {
                                        Log($"Connected to {client}");
                                    }
                                    else
                                    {
                                        Log($"Rejecting {client}, thumbprint is not authorized.");
                                        Log($"You can use the `/ACCEPT <thumbprint>` and `/BAN <thumbprint>` commands to authorized/deauthorize.");
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                var data = rsa.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                                if (isSTUN)
                                {
                                    // TODO: stun
                                }
                                else
                                {
                                    var message = Encoding.UTF8.GetString(data);
                                    Log($"({DateTime.UtcNow.ToString("HH:mm:ss")}) {client}> {message}");
                                }
                            }
                        }
                        var count = (expectedSize > 0)
                            ? expectedSize
                            : 4;
                        var cb = 0;
                        try
                        {
                            // TODO: implement PING, and then set a timeout for this read op that is (ping_interval*1.5) (ie. if no read within ping interval + grace period assume a dead link.)
                            var readTimeoutToken = new CancellationTokenSource(TimeSpan.FromMinutes(2)).Token;
                            cb = await stream.ReadAsync(buf, writeOffset, count, readTimeoutToken);
                        }
                        catch (Exception ex)
                        {
                            // NOP: the reasons for a failed read are all valid, and should result in a disconnect sequence
                            break;
                        }
                        writeOffset += cb;
                        if (cb == 0)
                        {
                            Log($"WORKER: Disconnection request detected for [{client.HostName}:{client.PortNumber}]");
                            // remote closure initiated
                            client.CancellationTokenSource.Cancel();
                            break;
                        }
                        else if (writeOffset >= buf.Length)
                        {
                            // TODO: gracefully d/c the offending client instead
                            throw new RankException($"Internal buffer overflow detected for [{client.HostName}:{client.PortNumber}]");
                        }
                        else if (readOffset > writeOffset)
                        {
                            throw new RankException($"Internal buffer underflow detected for [{client.HostName}:{client.PortNumber}]");
                        }
                        else if (readOffset == writeOffset && expectedSize == 0)
                        {
                            // the logic basically states if we're not expecting data, reset buffer state to avoid overflow
                            readOffset = 0;
                            writeOffset = 0;
                        }
                    }
                    stream.Close(10 * 1000);
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
            finally
            {
                client.TcpClient.Close();
                client.TcpClient.Dispose();
                client.TcpClient = null;
                Log($"WORKER: Disconnected from client");
            }
        }

    }
}
