using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CQ
{
    public sealed class ClientState :
        IDisposable
    {
        public ClientState(
            string hostName,
            int portNumber,
            TcpClient client)
        {
            HostName = hostName;
            PortNumber = portNumber;
            TcpClient = client;
        }

        private RSA _rsa;

        ~ClientState()
        {
            Dispose(false);
        }

        public CancellationTokenSource CancellationTokenSource { get; set; }

        public string Alias { get; set; }

        public string HostName { get; set; }

        public int PortNumber { get; set; }

        public RSA RSA { get; set; }

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
