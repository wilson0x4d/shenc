using CQ.Crypto;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using X4D.Diagnostics.Logging;

namespace CQ.Network
{
    /// <summary>
    /// Represents a "connection" to a "peer".
    /// <para>
    /// There may be many connections to a "peer", for example, a Peer may be
    /// connected via a Mobile App and also a Desktop App at the same time.
    /// </para>
    /// </summary>
    public sealed class CQConnection :
        IDisposable
    {
        private readonly CancellationTokenSource _cancellationTokenSource;

        private readonly Crypt _crypt;

        private readonly Action<string> _onStatusChange;

        private int _idealFlushBlockCount = 1024 / 4; // TODO: somewhat arbitrary

        private TcpClient _tcpClient;

        private Stream _inputStream;

        private Stream _outputStream;

        /// <summary>
        /// The <see cref="Task"/> responsible for managing this connection.
        /// </summary>
        private Task _worker;

        private CQConnection(
            Crypt crypt,
            string hostName,
            int portNumber,
            Action<string> onStatusChange)
        {
            _cancellationTokenSource = new CancellationTokenSource();
            _crypt = crypt;
            HostName = hostName;
            PortNumber = portNumber;
            _onStatusChange = onStatusChange;
            Peer = new CQPeer();
        }

        // TODO: dispose
        ~CQConnection()
        {
            Dispose(false);
        }

        public event EventHandler<EventArgs> ConversationEnded;

        public event EventHandler<MessageReceivedEventArgs> MessageReceived;

        // TODO: dispose
        public DateTime LastActiveTime { get; private set; }

        /// <summary>
        /// <para>
        /// (Immutable) Unlike <see cref="CQPeer.HostName"/>, this value does
        /// not change once it has been set.
        /// </para>
        /// </summary>
        public string HostName { get; private set; }

        /// <summary>
        /// <para>
        /// (Immutable) Unlike <see cref="CQPeer.PortNumber"/>, this value
        /// does not change once it has been set.
        /// </para>
        /// </summary>
        public int PortNumber { get; private set; }

        /// <summary>
        /// The <see cref="CQPeer"/> this connection is associated with.
        /// </summary>
        public CQPeer Peer { get; private set; }

        /// <summary>
        /// Used to create a CQConnection not-yet-connected to a remote.
        /// </summary>
        /// <returns>
        /// The returned <see cref="CQConnection"/> is valid for all uses.
        /// </returns>
        public static async Task<CQConnection> Create(
            Crypt crypt,
            string hostName,
            int portNumber,
            RSA rsa,
            Action<string> onStatusChange)
        {
            var connection = new CQConnection(crypt, hostName, portNumber, onStatusChange);

            $"Establishing connection to [{hostName}:{portNumber}]..".Log();
            var tcpClient = new TcpClient();
            tcpClient.NoDelay = true;
            tcpClient.ReceiveBufferSize = 16;
            await tcpClient.ConnectAsync(hostName, portNumber);
            connection._tcpClient = tcpClient;

            $"Initiating conversation with [{hostName}:{portNumber}]..".Log();
            await connection.InitiateConversation(rsa);

            // NOTE: the returned connection is valid for all uses. ha
            //       thumbprint, alias, and is actively sending/receiving data..
            return connection;
        }

        /// <summary>
        /// Used to create a CQConnection for a TcpClient accepted by a listener.
        /// </summary>
        /// <param name="tcpClient"></param>
        /// <returns></returns>
        public static async Task<CQConnection> Create(
            Crypt crypt,
            TcpClient tcpClient,
            RSA rsa,
            Action<string> onStatusChange)
        {
            var ipEndPoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint;
            var hostName = ipEndPoint.Address.ToString(); // TODO: reverse dns?
            var portNumber = ipEndPoint.Port;
            var connection = new CQConnection(crypt, hostName, portNumber, onStatusChange);
            connection._tcpClient = tcpClient;

            $"Accepting conversation with [{hostName}:{portNumber}]..".Log();
            await connection.AcceptConversation(rsa);

            // NOTE: the returned connection is valid for all uses. ha
            //       thumbprint, alias, and is actively sending/receiving data..
            return connection;
        }

        public async Task Ping()
        {
            $"{nameof(Ping)} is not implemented.".Log();
            //if (DateTime.UtcNow - LastActiveTime > s_minIdlePeriod)
            //{
            //    await WriteFlushBlock();
            //}
            await Task.CompletedTask;
        }

        public async Task AcceptConversation(RSA rsa)
        {
            // initial streams are "in the clear"
            _outputStream = _tcpClient.GetStream();
            _inputStream = _tcpClient.GetStream();

            /*
             *
             * connection negotiation starts with the client (initiater) not
             * the server (listener).
             *
             * 1. initiator sends pubkey, in the clear
             * 2. listener sends pubkey, encrypted with initiator pubkey
             * 3. initiator sends aes key, encrypted with listener pubkey
             * 4. listener sends aes key, encrypted with initiator aes key
             *
             * upon success communication continues over unidirectional,
             * encrypted channels.
             *
             */

            // expect pubkey (in the clear)
            var remoteRsaExpectedSize = await ReadMessageLength();
            var remoteRsaData = await ReadMessagePayload(
                _inputStream,
                remoteRsaExpectedSize,
                _cancellationTokenSource.Token);
            var remoteRsaJson = Encoding.UTF8.GetString(remoteRsaData);
            var remoteRsaParameters = JsonConvert.DeserializeObject<dynamic>(
                remoteRsaJson);

            var remoteRSA = RSA.Create();
            remoteRSA.ImportParameters(
                new RSAParameters
                {
                    Exponent = Convert.FromBase64String(
                        Convert.ToString(remoteRsaParameters.E)),
                    Modulus = Convert.FromBase64String(
                        Convert.ToString(remoteRsaParameters.M)),
                });

            var thumbprint = _crypt.GetThumbprint(remoteRSA);
            Peer.Thumbprint = thumbprint;

            /*
            // check client pubkey thumbprint against whitelist, if not in
            // whitelist then force a disconnect
            if (_whitelist.TryGetAlias(thumbprint, out string alias))
            {
                Peer.Alias = alias;
                _onStatusChange($"Connected to {Peer}".Log());
            }
            else
            {
                Peer.Alias = Peer.Thumbprint;
                _onStatusChange($@"Rejecting {Peer}, thumbprint is not authorized.
You can use the `/WHITELIST <thumbprint>` and `/BAN <thumbprint>` commands to authorized/deauthorize.".Log());
                return;
            }
            */

            // send pubkey (in the clear)
            var rsaParameters = rsa.ExportParameters(false);
            var pubkey = JsonConvert.SerializeObject(new
            {
                E = rsaParameters.Exponent,
                M = rsaParameters.Modulus,
            });
            {
                var buf = Encoding.UTF8.GetBytes(pubkey);
                await WriteMessage(buf);
            }

            // expect AES key (encrypted with our pubkey)
            var remoteAesExpectedSize = await ReadMessageLength();
            var remoteAesBytes = await ReadMessagePayload(_inputStream, remoteAesExpectedSize, _cancellationTokenSource.Token);
            remoteAesBytes = rsa.Decrypt(remoteAesBytes, RSAEncryptionPadding.Pkcs1);
            var remoteAesJson = Encoding.UTF8.GetString(remoteAesBytes);
            var remoteAesParameters = JsonConvert.DeserializeObject<dynamic>(remoteAesJson);

            var remoteAes = Aes.Create();
            remoteAes.Key = remoteAesParameters.K;
            remoteAes.IV = remoteAesParameters.V;

            // send our AES key (encrypted with remote pubkey)
            Aes aes = Aes.Create();
            var aesJson = JsonConvert.SerializeObject(new
            {
                K = aes.Key,
                V = aes.IV
            });
            var aesBytes = Encoding.UTF8.GetBytes(aesJson);
            aesBytes = remoteRSA.Encrypt(aesBytes, RSAEncryptionPadding.Pkcs1);
            await WriteMessage(aesBytes, true); // NOTE: the flush block must come encrypted

            // continue communication using aes keys (rsa keys can be discarded)
            _inputStream = new CryptoStream(_inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            var encryptor = remoteAes.CreateEncryptor();
            // _idealFlushBlockCount = ((encryptor.InputBlockSize / 4) + 1);
            _outputStream = new CryptoStream(_outputStream, encryptor, CryptoStreamMode.Write);

            await WriteFlushBlock();
            _worker = EnterConversationLoop();
        }

        public async Task EndConversation(string reason = null)
        {
            try
            {
                if (!string.IsNullOrEmpty(reason))
                {
                    var buf = Encoding.UTF8.GetBytes($"DISCONNECT: {reason}");
                    await WriteMessage(buf);
                    // TODO: force flush of network buffers instead of 'arbitrary' Task.Delay
                    await Task.Delay(1000);
                }
                _cancellationTokenSource.Cancel();
                if (_worker != null)
                {
                    await _worker;
                }
            }
            catch (Exception ex)
            {
                ex.Log();
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// Writes both message header and payload (aka "the message".)
        /// </summary>
        /// <param name="buf"></param>
        /// <param name="hasMoreData"></param>
        /// <returns></returns>
        /// <remarks>
        /// When <paramref name="hasMoreData"/> is set to `true`, <see
        /// cref="WriteMessage"/> will NOT write a flush block. Useful for
        /// implementing something like a file transfer protocol where flush
        /// blocks would only increase transfer overhead.
        /// </remarks>
        public async Task WriteMessage(byte[] buf, bool hasMoreData = false)
        {
            var ostream = _outputStream;
            lock (ostream)
            {
                ostream.Write(BitConverter.GetBytes(buf.Length), 0, 4);
                ostream.Write(buf, 0, buf.Length);
            }
            /*
            // NOTE: paying for this copy is cheaper than halding a lock which spans two synchronized tasks
            var temp = buf;
            buf = new byte[temp.Length + 4];
            Array.Copy(temp, 0, buf, 4, temp.Length);
            Array.Copy(BitConverter.GetBytes(temp.Length), 0, buf, 0, 4);
            await _outputStream.WriteAsync(buf, 0, buf.Length, _cancellationTokenSource.Token);
            LastActiveTime = DateTime.UtcNow;
            */
            if (!hasMoreData)
            {
                await WriteFlushBlock();
            }
        }

        public async Task Shutdown(string message)
        {
            $"{nameof(Shutdown)} is not implemented.".Log();
            // TODO: send final message (ie. QUIT message, BAN message, etc.)
            // TODO: send buffers
            // TODO: tcpclient
            await Task.CompletedTask;
        }

        public override string ToString()
        {
            return $"{HostName}:{PortNumber}";
        }

        /// <summary>
        /// Initiates a conversation between two endpoints. The initiator is
        /// the endpoint which estbalished the connection (not the one which
        /// was listening.)
        /// <para>
        /// The distinction of "Initiator" is only relevant for connection
        /// handshake (initiator writes first, listener writes last.)
        /// </para>
        /// </summary>
        /// <param name="rsa"></param>
        /// <remarks>
        /// connection negotiation starts with the client(initiater) not the server(listener).
        ///
        /// 1. initiator sends pubkey, in the clear
        /// 2. listener sends pubkey, in the clear
        /// 3. initiator sends aes key, encrypted with listener pubkey
        /// 4. listener sends aes key, encrypted with initiator pubkey
        /// 5.
        ///
        /// upon success communication continues over unidirectional,
        /// encrypted channels.
        /// </remarks>
        private async Task InitiateConversation(RSA rsa)
        {
            if (_worker != null)
            {
                throw new InvalidOperationException("Conversation already initiated.");
            }

            // TODO: should hold write-lock until success/fail
            // TODO: separate "initiator-handshake" from "worker loop" -- do this for both "initiator-handshake" as well as "listener-handshake"

            // initial streams are "in the clear"
            _outputStream = _tcpClient.GetStream();
            _inputStream = _tcpClient.GetStream();

            // send pubkey (in the clear)
            var rsaParameters = rsa.ExportParameters(false);
            var pubkey = JsonConvert.SerializeObject(new
            {
                E = rsaParameters.Exponent,
                M = rsaParameters.Modulus
            });
            var pubkeyBytes = Encoding.UTF8.GetBytes(pubkey);

            await WriteMessage(pubkeyBytes);

            // expect pubkey (in the clear)
            var remoteRsaExpectedSize = await ReadMessageLength();
            var remoteRsaData = await ReadMessagePayload(
                _inputStream,
                remoteRsaExpectedSize,
                _cancellationTokenSource.Token);
            var remoteRsaJson = Encoding.UTF8.GetString(remoteRsaData);
            var remoteRsaParameters = JsonConvert.DeserializeObject<dynamic>(
                remoteRsaJson);

            var remoteRSA = RSA.Create();
            remoteRSA.ImportParameters(
                new RSAParameters
                {
                    Exponent = Convert.FromBase64String(
                        Convert.ToString(remoteRsaParameters.E)),
                    Modulus = Convert.FromBase64String(
                        Convert.ToString(remoteRsaParameters.M)),
                });

            var thumbprint = _crypt.GetThumbprint(remoteRSA);
            Peer.Thumbprint = thumbprint;

            /*
            // check thumbprint against whitelist, if not in whitelist then
            // force a disconnect
            if (_whitelist.TryGetAlias(thumbprint, out string alias))
            {
                Peer.Alias = alias;
                _onStatusChange($"Connected to {Peer}".Log());
            }
            else
            {
                Peer.Alias = Peer.Thumbprint;
                _onStatusChange($@"Rejecting {Peer}, thumbprint is not authorized.
You can use the `/WHITELIST <thumbprint>` and `/BAN <thumbprint>` commands to authorized/deauthorize.".Log());
                return;
            }
            */

            // send our AES key (encrypted with remote pubkey)
            var aes = Aes.Create();
            var aesKey = aes.Key;
            var aesIV = aes.IV;
            var aesJson = JsonConvert.SerializeObject(new
            {
                K = Convert.ToBase64String(aes.Key),
                V = Convert.ToBase64String(aes.IV)
            });
            var aesJsonBytes = Encoding.UTF8.GetBytes(aesJson);
            aesJsonBytes = remoteRSA.Encrypt(aesJsonBytes, RSAEncryptionPadding.Pkcs1);
            await WriteMessage(aesJsonBytes, true); // NOTE: flush block must come encrypted

            // expect remote AES key (encrypted with our pubkey)
            var remoteAesExpectedSize = await ReadMessageLength();
            var remoteAesBytes = await ReadMessagePayload(
                _inputStream,
                remoteAesExpectedSize,
                _cancellationTokenSource.Token);
            remoteAesBytes = rsa.Decrypt(remoteAesBytes, RSAEncryptionPadding.Pkcs1);
            var remoteAesJson = Encoding.UTF8.GetString(remoteAesBytes);
            var remoteAesParameters = JsonConvert.DeserializeObject<dynamic>(remoteAesJson);
            var remoteAes = Aes.Create();
            remoteAes.Key = Convert.FromBase64String(
                Convert.ToString(remoteAesParameters.K));
            remoteAes.IV = Convert.FromBase64String(
                Convert.ToString(remoteAesParameters.V));

            // continue communication using aes keys (rsa keys can be discarded)
            _inputStream = new CryptoStream(_inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            var encryptor = remoteAes.CreateEncryptor();
            //_idealFlushBlockCount = ((encryptor.InputBlockSize / 4) + 1);
            _outputStream = new CryptoStream(_outputStream, encryptor, CryptoStreamMode.Write);

            await WriteFlushBlock();
            _worker = EnterConversationLoop();
        }

        private async Task EnterConversationLoop()
        {
            $"{nameof(EnterConversationLoop)}({this})".Log();
            // NOTE: in terms of networking, this task is the only 'receiver'
            // and it is the same logic regardless of who initiated the conversation.
            try
            {
                while (!_cancellationTokenSource.IsCancellationRequested)
                {
                    var expectedSize = await ReadMessageLength(); //
                    var data = await ReadMessagePayload(
                        _inputStream,
                        expectedSize,
                        _cancellationTokenSource.Token);

                    var message = Encoding.UTF8.GetString(data);
                    try
                    {
                        MessageReceived?.Invoke(this, new MessageReceivedEventArgs
                        {
                            Peer = Peer,
                            Message = message
                        });
                    }
                    catch (Exception ex)
                    {
                        ex.Log();
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                // NOP: the reasons for a failed read are all valid, and
                // should result in a disconnect sequence, only logged as a warning
                ex.Log(System.Diagnostics.TraceEventType.Warning);
            }
            finally
            {
                try
                {
                    ConversationEnded?.Invoke(this, new EventArgs());
                }
                catch (Exception ex)
                {
                    ex.Log();
                }
            }
        }

        //private async Task OnPingReceived(bool pong = false)
        //{
        //    var expectedSize = await ReadMessageLength(
        //        _inputStream,
        //        _cancellationTokenSource.Token);
        //    var data = await ReadMessagePayload(
        //        _inputStream,
        //        expectedSize,
        //        _cancellationTokenSource.Token);
        //    if (pong)
        //    {
        //        // NOTE: `data` is an RNG blob, so discarded
        //        // TODO: PONG! or dead peer
        //    }
        //}

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <remarks>
        /// During negotiate process (possibly others) we require cipher block frames to
        /// advance in a timely fashion. To acheive this we send pad bytes which coerces
        /// streams to flush their data.
        /// </remarks>
        private async Task<int> ReadMessageLength()
        {
            var len = 0;
            var buf = new byte[4];
            do
            {
                var i = await _inputStream.ReadAsync(buf, 0, 4, _cancellationTokenSource.Token);
                while (i < 4)
                {
                    i += await _inputStream.ReadAsync(buf, i, 4 - i, _cancellationTokenSource.Token);
                }
                len = BitConverter.ToInt32(buf, 0);
            } while (len == 0 && !_cancellationTokenSource.IsCancellationRequested);
            return len;
        }

        private async Task<byte[]> ReadMessagePayload(
            Stream inputStream,
            int expectedSize,
            CancellationToken token)
        {
            var buf = new byte[expectedSize];
            var offset = 0;
            while (offset < expectedSize)
            {
                offset += await inputStream.ReadAsync(buf, offset, expectedSize - offset);
            }
            return buf;
        }

        private async Task WriteFlushBlock()
        {
            // a "flush block" is a block of repeating 4-byte NUL values
            // written with the intent of causing block ciphers to complete
            // 'pending blocks' and also to ceorce network buffers into
            // performing sends/receives. an ideal block size is a single
            // block cipher input, plus 4 bytes.
            //
            // a "flush block" would normally be sent after every message,
            // except in the case `WriteMessage()` is called with
            // `hasMoreData` set to `true`. For this reason `WriteFlushBlock`
            // is not exposed to consumers.
            /*
            var buf = new byte[4];
            for (int i = 0; i < _idealFlushBlockCount; i++)
            {
                await _outputStream.WriteAsync(buf, 0, 4);
            }
            */
            var buf = new byte[4 * _idealFlushBlockCount];
            await _outputStream.WriteAsync(buf, 0, buf.Length);
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                GC.SuppressFinalize(this);
            }

            try
            {
                _cancellationTokenSource?.Cancel();
            }
            catch { /* NOP */ }

            try
            {
                _inputStream?.Dispose();
            }
            catch { /* NOP */ }

            try
            {
                _outputStream?.Dispose();
            }
            catch { /* NOP */ }

            try
            {
                _tcpClient?.Dispose();
            }
            catch { /* NOP */ }
        }

        public sealed class MessageReceivedEventArgs :
            EventArgs
        {
            /// <summary>
            /// The associated <see cref="CQPeer"/>.
            /// </summary>
            public CQPeer Peer { get; set; }

            /// <summary>
            /// The message received.
            /// </summary>
            public string Message { get; set; }
        }
    }
}
