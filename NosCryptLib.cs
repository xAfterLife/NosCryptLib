using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace NosCryptLib
{
    public class NFile
    {
        public string name { get; set; }
        public int fileNumber { get; set; }
        public int isDat { get; set; }
        public byte[] data { get; set; }

        public NFile(string _name, int _fileNumber, int _isDat, byte[] _data)
        {
            name = _name;
            fileNumber = _fileNumber;
            isDat = _isDat;
            data = _data;
        }
    }

    public class NFile2
    {
        public int ntHeaderNumber { get; set; }
        public int ID { get; set; }
        public int creationDate { get; set; }
        public byte[] Data { get; set; }
        public bool isCompressed { get; set; }

        public NFile2(int _ntHeaderNumber, int _ID, int _creationDate, byte[] _Data, bool _isCompressed)
        {
            ntHeaderNumber = _ntHeaderNumber;
            ID = _ID;
            creationDate = _creationDate;
            Data = _Data;
            isCompressed = _isCompressed;
        }
    }

    public static class NosTlib
    {
        private static readonly byte[] cryptoArray = { 0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x0A, 0x00 };

        private static byte[] decrypt(byte[] array)
        {
            List<byte> decryptedFile = new List<byte>();
            int currindex = 0;
            while (currindex < array.Length)
            {
                char currentByte = Convert.ToChar(array[currindex++]);
                if (currentByte == 0xFF)
                {
                    decryptedFile.Add(0xD);
                    continue;
                }

                int validate = currentByte & 0x7F;

                if ((currentByte & 0x80) != 0)
                {
                    for (; validate > 0; validate -= 2)
                    {
                        if (currindex >= array.Length)
                        {
                            break;
                        }

                        currentByte = Convert.ToChar(array[currindex++]);

                        decryptedFile.Add(cryptoArray[(currentByte & 0xF0) >> 4]);
                        if (validate <= 1)
                        {
                            break;
                        }

                        if (cryptoArray[currentByte & 0xF] == 0)
                        {
                            break;
                        }

                        decryptedFile.Add(cryptoArray[currentByte & 0xF]);
                    }
                }
                else
                {
                    for (; validate > 0; --validate)
                    {
                        if (currindex >= array.Length)
                        {
                            break;
                        }

                        currentByte = Convert.ToChar(array[currindex++]);
                        decryptedFile.Add(Convert.ToByte(currentByte ^ 0x33));
                    }
                }
            }

            return decryptedFile.ToArray();
        }

        public static List<NFile> GetNFiles(FileStream f)
        {
            List<NFile> retList = new List<NFile>();

            f.Seek(0, SeekOrigin.Begin);
            int fileAmount = f.readNextInt();
            for (int i = 0; i < fileAmount; i++)
            {
                int fileNumber = f.readNextInt();
                int stringNameSize = f.readNextInt();
                string stringName = f.readString(stringNameSize);
                int isDat = f.readNextInt();
                int fileSize = f.readNextInt();
                byte[] fileContent = f.readLength(fileSize);

                retList.Add(new NFile(stringName, fileNumber, isDat, decrypt(fileContent)));
            }
            return retList;
        }
    }

    public static class Helpers
    {
        public static int readNextInt(this FileStream fileSteam)
        {
            byte[] buffer = new byte[4];
            fileSteam.Read(buffer, 0, 4);
            return BitConverter.ToInt32(buffer, 0);
        }

        public static string readString(this FileStream fileStream, int count)
        {
            byte[] buffer = new byte[count];
            fileStream.Read(buffer, 0, count);
            return Encoding.Default.GetString(buffer);
        }

        public static byte[] readLength(this FileStream fileStream, int count)
        {
            byte[] buffer = new byte[count];
            fileStream.Read(buffer, 0, count);
            return buffer;
        }

        public static byte[] readLengthAt(this FileStream fileStream, int count, long position)
        {
            byte[] buffer = new byte[count];
            long currPos = fileStream.Position;
            fileStream.Seek(position, SeekOrigin.Begin);
            fileStream.Read(buffer, 0, count);
            fileStream.Seek(currPos, SeekOrigin.Begin);
            return buffer;
        }
    }

    public static class NosZlib
    {
        const int NOS_HEADER_SIZE = 0x10;

        private static byte[] toBigEndian(this int value)
        {
            byte[] ret = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian) Array.Reverse(ret);
            return ret;
        }

        private static int getNTHeaderNumber(byte[] array)
        {
            if (Convert.ToString(array.Skip(0).Take(7)) == "NT Data") return Convert.ToInt32(array.Skip(8).Take(2));
            else if (Convert.ToString(array.Skip(0).Take(10)) == "NT Data") return 101;
            else if (Convert.ToString(array.Skip(0).Take(11)) == "CCINF V1.20") return 102;
            else if (Convert.ToString(array.Skip(0).Take(10)) == "ITEMS V1.0") return 103;
            else return 199;
        }

        private static void fakeUncompress(ref byte[] data)
        {
            byte[] tmpArr = new byte[data.Length];
            using (DeflateStream ds = new DeflateStream(new MemoryStream(data), CompressionMode.Decompress))
            {
                ds.Read(tmpArr, 0, data.Length);
            }
            data = tmpArr;
        }

        public static List<NFile2> decrypt(FileStream file)
        {
            List<NFile2> files = new List<NFile2>();

            file.Seek(0, SeekOrigin.Begin);
            byte[] header = file.readLength(NOS_HEADER_SIZE);

            int ntHeaderNumber = getNTHeaderNumber(header);
            int fileAmount = file.readNextInt();
            byte[] separatorByte = file.readLength(1);

            for (int i = 0; i != fileAmount; ++i)
            {
                int id = file.readNextInt();
                int offset = file.readNextInt();
                long previousOffset = file.Position;

                file.Seek(offset, SeekOrigin.Current);

                int creationDate = file.readNextInt();
                int dataSize = file.readNextInt();
                int compressedDataSize = file.readNextInt();
                bool isCompressed = Convert.ToBoolean(file.readLengthAt(1, 0));
                byte[] data = file.readLength(compressedDataSize);
                if (isCompressed)
                {
                    fakeUncompress(ref data);
                }
                files.Add(new NFile2(ntHeaderNumber, id, creationDate, data, isCompressed));
                file.Seek(previousOffset, SeekOrigin.Begin);
            }

            return files;
        }
    }
}
