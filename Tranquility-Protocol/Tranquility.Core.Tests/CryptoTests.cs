using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Xunit;

namespace Tranquility.Core.Tests
{
    public class CryptoTests
    {
        [Fact]
        public void DiffieHellmanGeneration()
        {
            using (var server = ECDiffieHellman.Create())
            using (var client = ECDiffieHellman.Create())
            {
                var serverKey = server.DeriveKeyMaterial(client.PublicKey);
                var clientKey = client.DeriveKeyMaterial(server.PublicKey);
                
                Assert.Equal(serverKey, clientKey);
            }
        }

        [Fact]
        public void AesTest()
        {
            var message = Encoding.UTF8.GetBytes("This message will be encrypted and decrypted.");
            
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.GenerateKey();
                aes.GenerateIV();
                
                var encrypted = Protocol.Encrypt(message, aes.Key, aes.IV);
                var decrypted = Protocol.Decrypt(encrypted, aes.Key, aes.IV);
            
                Assert.Equal(message, decrypted);
            }
        }

        [Fact]
        public void CrcTest()
        {
            var obj1 = Enumerable.Repeat<Byte>(0xFF, 4).ToArray();
            var obj3 = Enumerable.Repeat<Byte>(0xDA, 4).ToArray();

            obj1 = Protocol.CalculateCrc(obj1);
            var obj2 = Protocol.CalculateCrc(obj1);
            obj3 = Protocol.CalculateCrc(obj3);
            
            Assert.Equal(obj1, obj2);
            Assert.NotEqual(obj1, obj3);
        }
        
        [Fact]
        public void PrependBytesTest()
        {
            Byte[] source = { 0x70, 0x71, 0x72, 0x73 };
            Byte[] insert = { 0xFA, 0xA4 };
            Byte[] validResult = { 0xFA, 0xA4, 0x70, 0x71, 0x72, 0x73 };

            var result = source.Prepend(insert);

            Assert.True(result.Length > source.Length);
            Assert.Equal(result, validResult);
        }
    }
}