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
    /// <summary>
    /// A quick and dirty tool for encrypting/decrypting text from a shell prompt.
    /// <para>Generates a one-time keypair, used for encryption/decryption.</para>
    /// <para>PUBLIC  key stored to `.pubkey` file.</para>
    /// <para>PRIVATE key stored to `.prikey` file.</para>
    /// <para>Offers a "chat" mode with whitelist authorization by thumbprint.</para>
    /// </summary>
    internal class Program
    {
        private static IDictionary<string, ClientState> _clients;

        private static IDictionary<string/*thumbprint*/, string/*display alias*/> _whitelist;

        private static TcpListener _listener;

        private static Process _debugLogCurrentProcess = null;

        private static void Main(string[] args)
        {
            try
            {
                if (args == null || args.Length == 0)
                {
                    PrintHelp();
                    return;
                }
                UpdateDynamicDns();
                var opcode = args[0].ToUpperInvariant();
                var keyid = args.Length > 1
                    ? args[1]
                    : default(string);
                var input = args.Length > 2
                    ? string.Join(" ", args.Skip(2))
                    : default(string);

                switch (opcode)
                {
                    case "CHAT":
                        {
                            if (string.IsNullOrWhiteSpace(keyid))
                            {
                                keyid = "chat";
                            }
                            var rsa = LoadKeypair(keyid, true); // ie. "My" key, the key used to decrypt incoming data
                            var cancellationTokenSource = new CancellationTokenSource();
                            SwitchToInteractiveMode(rsa, cancellationTokenSource)
                                .Wait();
                        }
                        return;

                    case "G":
                        GenerateKeypair(keyid);
                        return;

                    case "E":
                        Encrypt(keyid, input);
                        break;

                    case "D":
                        Decrypt(keyid, input);
                        break;

                    case "H":
                        Hash(keyid);
                        break;

                    default:
                        PrintHelp();
                        return;
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
        }

        private static void Hash(string keyid)
        {
            using (var rsa = LoadKeypair(keyid, false))
            {
                var thumbprint = GetThumbprint(rsa);
            }
        }

        private static string WhatsMyIP()
        {
            var webClient = new WebClient();
            webClient.Headers.Add("User-Agent", "shenc/0.1 shenc@mrshaunwilson.com");
            var response = webClient.DownloadString("https://ipapi.co/json/");
            dynamic obj = Newtonsoft.Json.JsonConvert.DeserializeObject(response);
            return (obj != null && !string.IsNullOrWhiteSpace(Convert.ToString(obj.ip)))
                ? obj.ip
                : Dns.GetHostEntry(IPAddress.Any).AddressList.FirstOrDefault();
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

        private static async Task SwitchToInteractiveMode(
            RSA rsa,
            CancellationTokenSource cancellationTokenSource)
        {
            _whitelist = LoadWhitelist()
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value);
            _clients = new Dictionary<string, ClientState>(StringComparer.OrdinalIgnoreCase);
            while (!cancellationTokenSource.IsCancellationRequested)
            {
                var command = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(command))
                {
                    continue;
                }
                var commandParts = command.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (commandParts.Length > 0)
                {
                    commandParts[0] = commandParts[0].ToUpperInvariant();
                    switch (commandParts[0])
                    {
                        case "/HELP":
                        case "/?":
                            PrintInteractiveHelp(commandParts.Length > 1 ? commandParts[1] : commandParts[0]);
                            break;

                        case "/QUIT":
                            try
                            {
                                // shutdown all client workers
                                lock (_clients)
                                {
                                    Task.WaitAll(_clients.Values.Select(StopClientWorker).ToArray());
                                }
                            }
                            finally
                            {
                                // shutdown self
                                cancellationTokenSource.Cancel(false);
                            }
                            break;

                        case "/LISTEN":
                            // TODO: control accept queue length
#pragma warning disable 4014
                            StartListening(
                                cancellationTokenSource,
                                commandParts.Length > 1 ? int.Parse(commandParts[1]) : 18593,
                                (client) => OnClientAcceptCallback(client, rsa));
#pragma warning restore 4014
                            break;

                        case "/DISCONNECT":
                            {
                                lock (_clients)
                                {
                                    var clients = _clients.Values
                                        .Where(client => commandParts.Any(e =>
                                               e.Equals(client.Alias, StringComparison.InvariantCultureIgnoreCase)
                                               || e.Equals($"{client.HostName}:{client.PortNumber}", StringComparison.OrdinalIgnoreCase)
                                               || e.Equals(client.Thumbprint, StringComparison.OrdinalIgnoreCase)));
                                    foreach (var client in clients)
                                    {
#pragma warning disable 4014
                                        StopClientWorker(client);
#pragma warning restore 4014
                                    }
                                }
                            }
                            break;

                        case "/CONNECT":
                            // treat each command input as a 'hostport'
                            commandParts.Skip(1).Select(async hostport =>
                            {
                                try
                                {
                                    var client = await ConnectTo(hostport, rsa);
                                }
                                catch (Exception ex)
                                {
                                    Log(ex);
                                }
                            })
                            .ToArray();
                            break;

                        case "/NOLISTEN":
                        case "/NOHOST":
                            StopListening();
                            break;

                        case "/PING":
                            {
                                // manual ping initiation for all hosts
                                var clients = default(IEnumerable<Task>);
                                lock (_clients)
                                {
                                    clients = _clients.Values
                                        .Select(PING)
                                        .ToArray(); // fire and forget.
                                }
                            }
                            break;

                        case "/ACCEPT":
                            {
                                if (commandParts.Length < 2)
                                {
                                    PrintInteractiveHelp(commandParts[0]);
                                }
                                else
                                {
                                    lock (_whitelist)
                                    {
                                        var thumbprint = commandParts[1];
                                        _whitelist.TryGetValue(thumbprint, out string L_alias);
                                        var alias = commandParts.Length > 2
                                            ? commandParts[2]
                                            : L_alias
                                            ?? thumbprint;
                                        _whitelist[thumbprint] = alias;
                                        lock (_clients)
                                        {
                                            foreach (var client in _clients.Values)
                                            {
                                                if (client.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    client.Alias = alias;
                                                }
                                            }
                                        }
                                        StoreWhitelist();
                                        Log($"ACCEPT: '{thumbprint}' => '{alias}'");
                                    }
                                }
                            }
                            break;

                        case "/BAN":
                            {
                                // remove from whitelist, each command part would be a new thumbprint
                                lock (_clients)
                                    lock (_whitelist)
                                    {
                                        var clients = _clients.Values
                                            .Where(client => commandParts.Any(e =>
                                                e.Equals(client.Alias, StringComparison.InvariantCultureIgnoreCase)
                                                || e.Equals($"{client.HostName}:{client.PortNumber}", StringComparison.OrdinalIgnoreCase)
                                                || e.Equals(client.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                                            .ToArray();

                                        var blacklist = _whitelist
                                            .Where(kvp => commandParts.Any(e =>
                                                kvp.Key.Equals(e, StringComparison.OrdinalIgnoreCase))
                                                || commandParts.Any(e => kvp.Value.Equals(e, StringComparison.OrdinalIgnoreCase)))
                                            .Select(kvp => kvp.Key)
                                            .ToArray();

                                        foreach (var thumbprint in blacklist)
                                        {
                                            _whitelist.Remove(thumbprint);
                                            Log($"BAN: {thumbprint}");
                                        }

                                        StoreWhitelist();

                                        foreach (var client in clients)
                                        {
#pragma warning disable 4014
                                            StopClientWorker(client);
#pragma warning restore 4014
                                        }
                                    }
                            }
                            break;

                        case "/WHITELIST":
                            {
                                lock (_whitelist)
                                {
                                    foreach (var thumbprint in _whitelist)
                                    {
                                        Log($"WHITELIST: {thumbprint}");
                                    }
                                }
                            }
                            break;

                        default:
                            {
                                // write message to all connected clients (like a chat room)
                                var tasks = default(IEnumerable<Task>);
                                var failures = new List<ClientState>();
                                lock (_clients)
                                {
                                    tasks = _clients.Values
                                        .Select(client => Task.Factory.StartNew(async () =>
                                        {
                                            try
                                            {
                                                Send(client, command);
                                            }
                                            catch (Exception ex)
                                            {
                                                Log(ex);
                                                failures.Add(client);
                                            }
                                            await Task.CompletedTask;
                                        }))
                                        .ToArray();
                                }
                                if (tasks.Any())
                                {
                                    Task.WaitAll(tasks.ToArray());
                                    tasks = failures.Select(client =>
                                    {
                                        try
                                        {
                                            lock (_clients)
                                            {
                                                if (_clients.Remove($"{client.HostName}:{client.PortNumber}"))
                                                {
                                                    DebugLog($"FAILED: Removed {client}");
                                                    return StopClientWorker(client);
                                                }
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Log(ex);
                                        }
                                        return Task.CompletedTask;
                                    }).ToArray();
                                    if (tasks.Any())
                                    {
                                        Task.WaitAll(tasks.ToArray());
                                    }
                                }
                            }
                            break;
                    }
                }
            }
        }

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

        private static void StoreWhitelist()
        {
            lock (_whitelist)
            {
                if (_whitelist.Count > 0)
                {
                    using (var writer = new StreamWriter(
                        File.Open("whitelist.txt", FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete)))
                    {
                        _whitelist.ToList().ForEach(kvp => writer.WriteLine($"{kvp.Key},{kvp.Value}"));
                        writer.Flush();
                        writer.Close();
                    }
                }
            }
        }

        private static IEnumerable<KeyValuePair<string, string>> LoadWhitelist()
        {
            if (File.Exists("whitelist.txt"))
            {
                using (var reader = new StreamReader(
                    File.Open("whitelist.txt", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)))
                {
                    var line = reader.ReadLine();
                    while (line != null)
                    {
                        var parts = line.Split(',');
                        var thumbprint = parts[0];
                        var alias = parts.Length > 1 ? parts[1] : thumbprint;
                        yield return new KeyValuePair<string, string>(thumbprint, alias);
                        line = reader.ReadLine();
                    }
                }
            }
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

        private static string GetThumbprint(RSA rsa)
        {
            var result = default(string);
            using (var sha1 = SHA1.Create())
            {
                var rsaParameters = rsa.ExportParameters(false);
                var json = JsonConvert.SerializeObject(rsaParameters);
                var data = Encoding.UTF8.GetBytes(json);
                var hashed = sha1.ComputeHash(data);
                result = string.Join(":", hashed.Select(e => e.ToString("X2")).ToArray()).ToLower();
            }
            return result;
        }

        private static string GetAlias(string thumbprint)
        {
            lock (_whitelist)
            {
                foreach (var kvp in _whitelist)
                {
                    if (kvp.Key.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return kvp.Value;
                    }
                }
            }
            return thumbprint;
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
            // TODO: move the following into a "disconnect all" variant of "/DISCONNECT"
            /*
            if (_clients != null && _clients.Count > 0)
            {
                // NOTE: this initiates asynchronous 'client worker
                //       stops' for all clients, and then waits on all of
                //       them to complete. it is done this way rather
                //       than one at a time so any delays can be
                //       overlapped (ie. it takes less time to shutdown
                //       for a large number of connections)
                Task.WaitAll(
                    _clients
                        .Values
                        .Select(client => StopClientWorker(client))
                        .ToArray());
                _clients.Clear();
            }
            */
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

        #region Interactive Help

        private static void PrintInteractiveHelp(string command)
        {
            switch (command.Trim('/'))
            {
                case "LISTEN":
                    Console.WriteLine(@"

Summary:
    Listen for connections on the specified port number.

Usage:
    /LISTEN [port-number]

    port-number = (optional) The Port Number to listen for
        connections on, defaults to port 18593.

 NOTE: Listening on more than one port is not supported.

 NOTE: The port may need to be added to your firewall.

See also: /ACCEPT, /NOLISTEN
");
                    break;

                case "NOLISTEN":
                    Console.WriteLine(@"

Summary:
    Stop listening for connections.

Usage:
    /NOLISTEN

See also: /DISCONNECT, /BAN, /LISTEN
");
                    break;

                case "CONNECT":
                    Console.WriteLine(@"

Summary:
    Connect a remote system.

Usage:
    /CONNECT <host[:port]>

    host = (required) a hostname or ip address of the
        remote system to connect to.

    port = (optional) The Port Number to listen for
        connections on, defaults to port 18593.

See also: /DISCONNECT
");
                    break;

                case "DISCONNECT":
                    Console.WriteLine(@"

Summary:
    Disconnect a remote system.

Usage:
    /DISCONNECT <alias|thumbprint|<host[:port]>]>

    Only 1 the 3 parameters shown are required:

    alias = (required) an alias previously assigned
        to a thumbrint associated with the remote 
        system.

    -or-

    thumbprint = (required) a thumbrint associated 
        with the remote system.

    -or-

    host = (required) a hostname or ip address of the
        remote system to connect to.

    port = (optional) The Port Number to listen for
        connections on, defaults to port 18593.

See also: /DISCONNECT
");
                    break;

                case "ACCEPT":
                    Console.WriteLine(@"

Summary:
    Accept a thumbprint/remote/client, and optionally
    assign it an alias, by adding it to the WHITELIST.

Usage:
    /ACCEPT <thumbprint> [alias]

    thumbprint = (required) a thumbrint associated 
        with the remote system.

    alias = (optional) an alias previously assigned
        to a thumbrint associated with the remote 
        system.

See also: /BAN
");
                    break;

                case "BAN":
                    Console.WriteLine(@"

Summary:
    Ban a thumbprint/remote/client by removing it from
    the WHITELIST.

Usage:
    /BAN <alias|thumbprint|<host[:port]>>

    alias = (required) an alias previously assigned
        to a thumbrint associated with the remote 
        system.

    -or-

    thumbprint = (required) a thumbrint associated 
        with the remote system.

    -or-

    host = (required) a hostname or ip address of the
        remote system to connect to.

    port = (optional) The Port Number to listen for
        connections on, defaults to port 18593.

See also: /BAN
");
                    break;

                case "WHITELIST":
                    Console.WriteLine(@"

Summary:
    Displays the current WHITELIST entries.

Usage:
    /WHITELIST

See also: /ACCEPT, /BAN
");
                    break;

                case "QUIT":
                    Console.WriteLine(@"

Summary:
    Quit, gracefully disconnecting all remotes.

Usage:
    /QUIT
");
                    break;

                case "HELP":
                default:
                    Console.WriteLine(@"

/HELP [command]

/LISTEN [port-number]
/NOLISTEN

/CONNECT <host>:<port>
/DISCONNECT <alias|<host>:<port>>

/ACCEPT <thumbprint> [alias]
/BAN <thumbprint|alias|<host>:<port>>
/WHITELIST

/QUIT
");
                    break;
            }
        }

        private static void PrintHelp() =>
            Console.WriteLine(@"
shenc g //generates a new keypair

shenc e [keyfile] [input] // encrypts a string or file using specified keypair
shenc d [keyfile] [input] // decrypts a string or file using specified keypair

shenc chat [keyfile] // enters into 'chat mode'

===
=== NO-IP Support:
===
=== In your app config, add two <appSettings/> keys:
===
<appSettings>
    <add key=""no-ip:hostname"" value=""w00tcakes.ddns.net""/>
    <add key=""no-ip:auth"" value=""UgkUnzZvIbmSX9Fp5ejRBtgpwsTHV/g+QB0=""/>
    <!-- optional keys, and their defaults
    <add key=""no-ip:key"" value=""chat""/>
    <add key=""no-ip:address"" value=""127.0.0.1""/>
    -->
</appSettings>
=== You can create an encrypted `auth` value like so:
shenc e chat noip-username:noip-password
=== Then copy-paste the base64-encoded value into your config.
=== ");

        #endregion Interactive Help

        #region TODO: use a real logging framework

        private static void Log(string text)
        {
            Console.WriteLine(text);
        }

        private static void Log(Exception ex)
        {
            try
            {
                var prefix = "";
                while (ex != null)
                {
                    var text = $@"{prefix}Exception: {ex.GetType().FullName}
Message: {ex.Message}
StackTrace: {ex.StackTrace}";
                    Console.Error.WriteLine(text);
                    DebugLog(text);
                    ex = ex.InnerException;
                    prefix = "Inner";
                }
            }
            catch (Exception L_ex)
            {
                Trace.TraceError($"{L_ex.Message}=>{L_ex.StackTrace}");
            }
        }

        private static void DebugLog(string text)
        {
            if (Debugger.IsAttached)
            {
                var processId = (_debugLogCurrentProcess ?? (_debugLogCurrentProcess = Process.GetCurrentProcess())).Id;
                Trace.WriteLine($"{DateTime.UtcNow:o} [{processId}] {text}");
            }
        }

        #endregion TODO: use a real logging framework

        private static RSA GenerateKeypair(string keyid = null)
        {
            keyid = keyid ?? $"{Guid.NewGuid()}";
            if (keyid.EndsWith(".prikey", StringComparison.OrdinalIgnoreCase) || keyid.EndsWith(".pubkey", StringComparison.OrdinalIgnoreCase))
            {
                keyid = keyid.Remove(keyid.Length - 7);
            }
            Console.WriteLine("Generating a new key, this could take a while.. please be patient.");
            var rsa = RSA.Create();
            rsa.KeySize = 8192;
            {
                var rsaParameters = rsa.ExportParameters(true);
                var json = JsonConvert.SerializeObject(new
                {
                    // dynamic type because `RSAParameters` does not serialize as expected
                    rsaParameters.D,
                    rsaParameters.DP,
                    rsaParameters.DQ,
                    rsaParameters.Exponent,
                    rsaParameters.InverseQ,
                    rsaParameters.Modulus,
                    rsaParameters.P,
                    rsaParameters.Q
                }, Formatting.Indented);
                var prikey = Encoding.UTF8.GetBytes(json);
                using (var file = File.Open($"{keyid}.prikey", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    file.Write(prikey, 0, prikey.Length);
                    file.Flush();
                    file.Close();
                }
                Console.WriteLine($"Generated PRIKEY file: {keyid}.prikey");
            }
            {
                var rsaParameters = rsa.ExportParameters(false);
                var json = JsonConvert.SerializeObject(new
                {
                    // dynamic type because `RSAParameters` does not serialize as expected
                    rsaParameters.D,
                    rsaParameters.DP,
                    rsaParameters.DQ,
                    rsaParameters.Exponent,
                    rsaParameters.InverseQ,
                    rsaParameters.Modulus,
                    rsaParameters.P,
                    rsaParameters.Q
                }, Formatting.Indented);
                var pubkey = Encoding.UTF8.GetBytes(json);
                using (var file = File.Open($"{keyid}.pubkey", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    file.Write(pubkey, 0, pubkey.Length);
                    file.Flush();
                    file.Close();
                }
                Console.WriteLine($"Generated PUBKEY file: {keyid}.pubkey");
            }
            return rsa;
        }

        private static RSA LoadKeypair(string keyid, bool generateIfMissing = false)
        {
            if (!File.Exists(keyid))
            {
                if (File.Exists($"{keyid}.prikey"))
                {
                    keyid = $"{keyid}.prikey";
                }
                else if (File.Exists($"{keyid}.pubkey"))
                {
                    keyid = $"{keyid}.pubkey";
                }
                else if (generateIfMissing)
                {
                    keyid = $"{keyid}.prikey";
                    return GenerateKeypair(keyid);
                }
                else
                {
                    throw new FileNotFoundException(keyid);
                }
            }
            using (var file = File.Open(keyid, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var buf = new byte[file.Length];
                var offset = 0;
                while (offset < buf.Length)
                {
                    offset += file.Read(buf, offset, buf.Length);
                }
                var json = Encoding.UTF8.GetString(buf);
                var parameters = JsonConvert.DeserializeObject<dynamic>(json); // dynamic type because `RSAParameters` does not deserialize as expected
                var rsaParameters = new RSAParameters
                {
                    D = parameters.D,
                    DP = parameters.DP,
                    DQ = parameters.DQ,
                    Exponent = parameters.Exponent,
                    InverseQ = parameters.InverseQ,
                    Modulus = parameters.Modulus,
                    P = parameters.P,
                    Q = parameters.Q
                };
                var rsa = RSA.Create();
                rsa.ImportParameters(rsaParameters);
                file.Close();
                Console.WriteLine($"Loaded Key '{keyid}'");
                return rsa;
            }
        }

        private static void EncryptText(string keyfile, string input)
        {
            var rsa = LoadKeypair(keyfile);
            var data = Encoding.UTF8.GetBytes(input);
            var edata = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            var output = Convert.ToBase64String(edata, Base64FormattingOptions.None);
            Console.WriteLine(output);
        }

        private static void EncryptFile(string keyfile, string input)
        {
            var rsa = LoadKeypair(keyfile);
            using (var infile = File.Open($"{input}", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var data = new byte[infile.Length];
                infile.Read(data, 0, data.Length);
                var edata = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                using (var outfile = File.Open($"{input}.out", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    outfile.Write(edata, 0, edata.Length);
                    outfile.Flush();
                    outfile.Close();
                }
                infile.Close();
            }
            Console.WriteLine($"Created: {input}.out");
        }

        private static void DecryptText(string keyfile, string input)
        {
            var rsa = LoadKeypair(keyfile);
            var edata = Convert.FromBase64String(input);
            var data = rsa.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
            var output = Encoding.UTF8.GetString(data);
            Console.WriteLine(output);
        }

        private static void DecryptFile(string keyfile, string input)
        {
            var rsa = LoadKeypair(keyfile);
            using (var infile = File.Open($"{input}", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                if (input.EndsWith(".out"))
                {
                    input = input.Substring(0, input.Length - 4);
                }
                var edata = new byte[infile.Length];
                infile.Read(edata, 0, edata.Length);
                var data = rsa.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                using (var outfile = File.Open($"{input}", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    outfile.Write(data, 0, data.Length);
                    outfile.Flush();
                    outfile.Close();
                }
                infile.Close();
            }
            Console.WriteLine($"Created: {input}");
        }

        private static void Encrypt(string keyfile, string input)
        {
            if (File.Exists(input))
            {
                EncryptFile(keyfile, input);
            }
            else
            {
                EncryptText(keyfile, input);
            }
        }

        private static void Decrypt(string keyfile, string input)
        {
            if (File.Exists(input))
            {
                DecryptFile(keyfile, input);
            }
            else
            {
                DecryptText(keyfile, input);
            }
        }

        private sealed class ClientState :
            IDisposable
        {
            private RSA _rsa;

            ~ClientState()
            {
                Dispose(false);
            }

            public CancellationTokenSource CancellationTokenSource { get; set; }

            public string Alias { get; set; }

            public string HostName { get; set; }

            public int PortNumber { get; set; }

            public RSA RSA
            {
                get
                {
                    return _rsa;
                }
                set
                {
                    if (_rsa != value)
                    {
                        _rsa = value;
                        if (_rsa != null)
                        {
                            Thumbprint = GetThumbprint(_rsa);
                            Alias = GetAlias(Thumbprint);
                        }
                        else
                        {
                            Thumbprint = "(null)";
                            Alias = $"{HostName}:{PortNumber}";
                        }
                    }
                }
            }

            public string Thumbprint { get; set; }

            public TcpClient TcpClient { get; set; }

            public Task Worker { get; set; }

            public override string ToString()
            {
                return $"{Alias ?? Thumbprint ?? HostName + ":" + PortNumber}";
            }

            public void Dispose()
            {
                Dispose(true);
            }

            private void Dispose(bool disposing)
            {
                try
                {
                    var rsa = RSA;
                    RSA = null;
                    if (rsa != null)
                    {
                        rsa.Dispose();
                    }
                }
                catch { /* NOP */ }
            }
        }
    }
}
