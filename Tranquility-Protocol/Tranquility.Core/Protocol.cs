using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Force.Crc32;

namespace Tranquility.Core
{
    public static class Protocol
    {
        // Incrementing protocol version breaks compatibility with previous versions
        // Use wisely!
        public static readonly Int32 Version = 1;
        
        public static Byte[] CreatePacketAsync(Byte[] packet, Int32 packetType)
        {
            var crc = CalculateCrc(packet);
            var type = BitConverter.GetBytes(packetType);
            packet = packet.Prepend(crc).Prepend(type);
            
            var size = BitConverter.GetBytes(packet.Length);
            packet = packet.Prepend(size);

            return packet;
        }

        public static Byte[] CreateEncryptedPacketAsync(Byte[] packet, Int32 packetType, Byte[] key, Byte[] iv)
        {
            var encryptedData = Encrypt(packet, key, iv);
            
            var crc = CalculateCrc(encryptedData);
            var type = BitConverter.GetBytes(packetType);
            
            encryptedData = packet.Prepend(crc).Prepend(iv).Prepend(type);

            var size = BitConverter.GetBytes(encryptedData.Length);
            encryptedData = encryptedData.Prepend(size);

            return encryptedData;
        }

        public static Byte[] Prepend(this Byte[] source, Byte[] toInsert)
        {
            var result = new Byte[source.Length + toInsert.Length];

            Array.Copy(toInsert, 0, result, 0, toInsert.Length);
            Array.Copy(source, 0, result, toInsert.Length, source.Length);

            return result;
        }

        public static Byte[] CalculateCrc(Byte[] data)
        {
            using (var crc = new Crc32CAlgorithm())
            {
                return crc.ComputeHash(data);
            }
        }
        
        public static Byte[] Encrypt(Byte[] data, Byte[] key, Byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.IV = iv;
                aes.Key = key;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                
                using (var ms = new MemoryStream())
                using (var crypto = aes.CreateEncryptor())
                using (var cs = new CryptoStream(ms, crypto, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }
        
        public static Byte[] Decrypt(Byte[] data, Byte[] key, Byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.IV = iv;
                aes.Key = key;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                
                using (var ms = new MemoryStream())
                using (var crypto = aes.CreateDecryptor())
                using (var cs = new CryptoStream(ms, crypto, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }

        public static Byte[] Serialize<T>(ref T packet) where T : struct
        {
            var size = Marshal.SizeOf(packet);
            var serializedData = new Byte[size];
            var ptr = Marshal.AllocHGlobal(size);
            
            Marshal.StructureToPtr(packet, ptr, true);
            Marshal.Copy(ptr, serializedData, 0, size);
            Marshal.FreeHGlobal(ptr);

            return serializedData;
        }

        public static T Deserialize<T>(Byte[] packetBytes)
        {
            var handle = GCHandle.Alloc(packetBytes, GCHandleType.Pinned);
            var packet = (T) Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return packet;
        }
    }
}
