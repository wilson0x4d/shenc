using System;
using System.Runtime.Serialization;

namespace CQ
{
    /// <summary>
    /// Provides identifying information about known peers.
    /// <para>
    /// A "peer" has zero or more connections, unlike most p2p systems where
    /// there is a 1:1 relationship between peers and connections. Peers are
    /// identified by their thumbprint (not their connection info.)
    /// </para>
    /// </summary>
    [DataContract]
    public sealed class CQPeer :
        IEquatable<CQPeer>, 
        IComparable<CQPeer>
    {
        /// <summary>
        /// <para>
        /// before a thumbprint has been determined for a connection, it
        /// should not be added to any maps
        /// </para>
        /// </summary>
        [DataMember(Name = "id", Order = 1)]
        public string Thumbprint { get; set; }

        /// <summary>
        /// An 'alias' for this peer, used for display and when parsing user
        /// input any time a "thumbprint" would be acceptable.
        /// <para>(Optional)</para>
        /// <para>
        /// May not contain ":" characters (ie. may not look like a thumbprint.)
        /// </para>
        /// </summary>
        [DataMember(Name = "alt", Order = 2)]
        public string Alias { get; set; }

        /// <summary>
        /// The (last known) Host or IP of the peer.
        /// <para>(Transient)</para>
        /// <para>Informative only. Not "trustworthy."</para>
        /// </summary>
        [DataMember(Name = "host", Order = 3)]
        public string HostName { get; set; }

        /// <summary>
        /// The (last known) Port Number of the peer.
        /// <para>(Transient)</para>
        /// <para>Informative only. Not "trustworthy."</para>
        /// </summary>
        [DataMember(Name = "port", Order = 4)]
        public int PortNumber { get; set; }

        public bool Equals(CQPeer other)
        {
            var result = other != null
                && (ReferenceEquals(this, other)
                    || Thumbprint?.Equals(other.Thumbprint) != false);
            return result;
        }

        public static bool operator ==(CQPeer lval, CQPeer rval)
        {
            var result = (ReferenceEquals(lval, null) && ReferenceEquals(rval, null))
                || (ReferenceEquals(lval, rval)
                || $"{lval?.Thumbprint}".Equals($"{rval?.Thumbprint}", StringComparison.OrdinalIgnoreCase));
            return result;
        }

        public static bool operator !=(CQPeer lval, CQPeer rval)
        {
            return !(lval == rval);
        }

        public override string ToString()
        {
            var result = string.IsNullOrWhiteSpace(Alias)
                ? Thumbprint
                : Alias;
            return result;
        }

        public override bool Equals(object obj)
        {
            return (this as IEquatable<CQPeer>).Equals(obj as CQPeer);
        }

        public override int GetHashCode()
        {
            if (string.IsNullOrWhiteSpace(Thumbprint))
            {
                throw new ArgumentException($"{nameof(Thumbprint)} cannot be null or whitespace.");
            }
            return Thumbprint.GetHashCode();
        }

        public int CompareTo(CQPeer other)
        {
            return $"{this}".CompareTo($"{other}");
        }
    }
}
