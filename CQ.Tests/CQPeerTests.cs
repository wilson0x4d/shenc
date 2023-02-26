using CQ.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CQ.Tests
{
    [TestClass]
    public class CQPeerTests
    {
        [TestMethod]
        public void CQPeer_SupportsNonReferenceEquals()
        {
            var crypt = new Crypt();
            var keyid1 = $"{Guid.NewGuid()}";
            var keyid2 = $"{Guid.NewGuid()}";
            var key1 = crypt.LoadKeypair(keyid1, true);
            var key2 = crypt.LoadKeypair(keyid2, true);
            var thumbprint1 = crypt.Hash(keyid1);
            var thumbprint2 = crypt.Hash(keyid2);
            var collection = new List<CQPeer>
            {
                new CQPeer
                {
                    Thumbprint = thumbprint1,
                },
                new CQPeer
                {
                    Thumbprint = thumbprint2,
                }
            };
            Assert.AreEqual(2, collection.Count);

            var count = collection.Count(peer => peer == new CQPeer
            {
                Thumbprint = thumbprint1
            });
            Assert.AreEqual(1, count);
        }

        [TestMethod]
        public void CQPeer_SupportsCollectionComparison()
        {
            var crypt = new Crypt();
            var keyid1 = $"{Guid.NewGuid()}";
            var keyid2 = $"{Guid.NewGuid()}";
            var key1 = crypt.LoadKeypair(keyid1, true);
            var key2 = crypt.LoadKeypair(keyid2, true);
            var thumbprint1 = crypt.Hash(keyid1);
            var thumbprint2 = crypt.Hash(keyid2);
            var collection = new List<CQPeer>
            {
                new CQPeer
                {
                    Thumbprint = thumbprint1,
                },
                new CQPeer
                {
                    Thumbprint = thumbprint2,
                }
            };
            Assert.AreEqual(2, collection.Count);

            var exists = collection.Contains(new CQPeer
            {
                Thumbprint = thumbprint1
            });
            Assert.IsNotNull(exists);

            var count = collection.Count(peer => peer == new CQPeer
            {
                Thumbprint = thumbprint2
            });
            Assert.AreEqual(1, count);
        }

        [TestMethod]
        public void CQPeer_SupportsDictionaryComparison()
        {
            var crypt = new Crypt();
            var keyid1 = $"{Guid.NewGuid()}";
            var keyid2 = $"{Guid.NewGuid()}";
            var key1 = crypt.LoadKeypair(keyid1, true);
            var key2 = crypt.LoadKeypair(keyid2, true);
            var thumbprint1 = crypt.Hash(keyid1);
            var thumbprint2 = crypt.Hash(keyid2);
            var dict = new Dictionary<CQPeer, string>
            {
                {
                    new CQPeer
                    {
                        Thumbprint = thumbprint1,
                    },
                    thumbprint1
                },
                {
                    new CQPeer
                    {
                        Thumbprint = thumbprint2,
                    },
                    thumbprint2
                }
            };
            Assert.AreEqual(2, dict.Count);

            var actual1 = dict[new CQPeer
            {
                Thumbprint = thumbprint1
            }];
            Assert.AreEqual(thumbprint1, actual1);

            var actual2 = dict[new CQPeer
            {
                Thumbprint = thumbprint2
            }];
            Assert.AreEqual(thumbprint2, actual2);
        }
    }
}
