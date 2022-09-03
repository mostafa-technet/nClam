namespace nClam
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Collections.Generic;
    using System.Linq;
    using System.Linq.Expressions;
    public class ClamClient : IClamClient
    {
        /// <summary>
        /// Maximum size (in bytes) which streams will be broken up to when sending to the ClamAV server.  Used in the SendAndScanFile methods.  128kb is the default size.
        /// </summary>
        public int MaxChunkSize { get; set; }

        /// <summary>
        /// Maximum size (in bytes) that can be streamed to the ClamAV server before it will terminate the connection. Used in the SendAndScanFile methods. 25mb is the default size.
        /// </summary>
        public long MaxStreamSize { get; set; }

        /// <summary>
        /// Address to the ClamAV server
        /// </summary>
        public string Server { get; set; }

        /// <summary>
        /// Port which the ClamAV server is listening on
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// A class to connect to a ClamAV server and request virus scans
        /// </summary>
        /// <param name="server">Address to the ClamAV server</param>
        /// <param name="port">Port which the ClamAV server is listening on</param>
        public ClamClient(string server, int port = 3310)
        {
            MaxChunkSize = 131072; //128k
            MaxStreamSize = 26214400; //25mb
            Server = server;
            Port = port;
        }
        const int CP_ACP = 0;
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int WideCharToMultiByte(uint CodePage, uint dwFlags,
   [MarshalAs(UnmanagedType.LPWStr)] string lpWideCharStr, int cchWideChar,
   [MarshalAs(UnmanagedType.LPArray)] Byte[] lpMultiByteStr, int cbMultiByte, IntPtr lpDefaultChar,
   out bool lpUsedDefaultChar);
        /// <summary>
        /// Helper method which connects to the ClamAV Server, performs the command and returns the result.
        /// </summary>
        /// <param name="command">The command to execute on the ClamAV Server</param>
        /// <param name="cancellationToken">cancellation token used in requests</param>
        /// <param name="additionalCommand">Action to define additional server communications.  Executed after the command is sent and before the response is read.</param>
        /// <returns>The full response from the ClamAV server.</returns>
        private async Task<string> ExecuteClamCommandAsync(string command, CancellationToken cancellationToken, Func<NetworkStream, CancellationToken, Task> additionalCommand = null)
        {
#if DEBUG
            var stopWatch = System.Diagnostics.Stopwatch.StartNew();
#endif
            string result;

            var clam = new TcpClient();
            try
            {
                await clam.ConnectAsync(Server, Port).ConfigureAwait(false);

                using (var stream = clam.GetStream())
                {
                    Encoding unicode = Encoding.Unicode;
                    Encoding utf8 = Encoding.UTF8;

                    byte[] unicodeBytes = unicode.GetBytes(command);

                    byte[] utf8Bytes = Encoding.Convert(unicode,
                                                         utf8,
                                                         unicodeBytes);
                    var commandText = String.Format("z{0}\0", command);
                    Int32 iNewDataLen = 0;
                    Byte[] byNewData = null;
                    bool bDefaultChar = false;

                    iNewDataLen = WideCharToMultiByte(CP_ACP, 0, commandText, commandText.Length, null, 0, IntPtr.Zero, out bDefaultChar);
                    byNewData = new Byte[iNewDataLen + 2];
                    iNewDataLen = WideCharToMultiByte(CP_ACP, 0, commandText, commandText.Length, byNewData, iNewDataLen, IntPtr.Zero, out bDefaultChar);
                    var commandBytes = byNewData;//Encoding.GetBytes(commandText);
                    await stream.WriteAsync(commandBytes, 0, commandBytes.Length, cancellationToken).ConfigureAwait(false);

                    if (additionalCommand != null)
                    {
                        await additionalCommand(stream, cancellationToken).ConfigureAwait(false);
                    }

                    using (var reader = new StreamReader(stream))
                    {
                        result = await reader.ReadToEndAsync().ConfigureAwait(false);

                        if (!String.IsNullOrEmpty(result))
                        {
                            //if we have a result, trim off the terminating null character
                            result = result.TrimEnd('\0');
                        }
                    }
                }
            }
            finally
            {
                if (clam.Connected)
                {
                    clam.Client.Dispose();
                }
            }
#if DEBUG
            stopWatch.Stop();
            System.Diagnostics.Debug.WriteLine("Command {0} took: {1}", command, stopWatch.Elapsed);
#endif
            return result;
        }
 
        private async Task<ClamScanResult[]> ExecuteClamCommandAsync(string[] commands, CancellationToken cancellationToken, Func<NetworkStream, CancellationToken, Task> additionalCommand = null)
        {
#if DEBUG
            var stopWatch = System.Diagnostics.Stopwatch.StartNew();
#endif
            List<string> results = new List<string>();
 byte[] strm = new byte[1024]; 
           TcpClient clam = new TcpClient();
            int i = 0;
           // var clam = new TcpClient();
            try
            {
                //if(!clam.Connected)
               
//                var stream = new MemoryStream(strm);

                await clam.ConnectAsync(Server, Port).ConfigureAwait(false);

                using (Stream stream1 = clam.GetStream())
                {
                    var cbytes = Encoding.UTF8.GetBytes(String.Format("zIDSESSION\0"));
                    await stream1.WriteAsync(cbytes, 0, cbytes.Length, cancellationToken).ConfigureAwait(false);
                    
                    for (i = 0; i < commands.Length; i++)
                    {
                        try
                        {
                            //   results.Add(await reader.ReadToEndAsync().ConfigureAwait(false));
                            // //System.Windows.Forms.MessageBox.Show(":" + commands[i]);
                            Encoding unicode = Encoding.Unicode;
                            Encoding utf8 = Encoding.UTF8;

                            byte[] unicodeBytes = unicode.GetBytes("z"+commands[i]+"\0");

                            byte[] utf8Bytes = Encoding.Convert(unicode,
                                                                 utf8,
                                                                 unicodeBytes);
                            var commandText = String.Format("z"+commands[i]+"\0");
                            Int32 iNewDataLen = 0;
                            Byte[] byNewData = null;
                            bool bDefaultChar = false;

                            iNewDataLen = WideCharToMultiByte(CP_ACP, 0, commandText, commandText.Length, null, 0, IntPtr.Zero, out bDefaultChar);
                            byNewData = new Byte[iNewDataLen + 2];
                            iNewDataLen = WideCharToMultiByte(CP_ACP, 0, commandText, commandText.Length, byNewData, iNewDataLen, IntPtr.Zero, out bDefaultChar);
                          //  var commandBytes = byNewData;//Encoding.GetBytes(commandText);
                            await stream1.WriteAsync(utf8Bytes, 0, utf8Bytes.Length, cancellationToken).ConfigureAwait(false);
                            byte[] buffer1 = new byte[512];
                            stream1.Read(buffer1, 0, buffer1.Length);
                            var s1 = Encoding.UTF8.GetString(buffer1);
                            ////System.Windows.Forms.MessageBox.Show(s1);
                            if (s1.Contains(": "))
                            {
                                results.Add(s1.Substring(s1.IndexOf(": ") + 1).Trim().Replace("\\\\?\\", "").TrimEnd('\0'));
                              //  //System.Windows.Forms.MessageBox.Show(results.Last());
                            }
                            /*
                    if (additionalCommand != null)
                    {
                        await additionalCommand(stream, cancellationToken).ConfigureAwait(false);
                    }*/

                            // await stream.FlushAsync();


                            //results.Add(Encoding.UTF8.GetString(buf1));
                        }
                        catch (Exception ex)
                        {
                             //System.Windows.Forms.MessageBox.Show(ex.ToString());
                        }
                        //      
                    } 
                    var cbytes2 = Encoding.UTF8.GetBytes("zEND\0");
                    await stream1.WriteAsync(cbytes2, 0, cbytes2.Length, cancellationToken).ConfigureAwait(false); 
                    // stream1.ReadTimeout = 100;
                    ////System.Windows.Forms.MessageBox.Show("");
                    byte[] buffer = new byte[512];
                    stream1.Read(buffer, 0, buffer.Length);
                    var s = Encoding.UTF8.GetString(buffer);
                   /* //System.Windows.Forms.MessageBox.Show(s);
                    if (s.Contains(": "))
                    {
                        results.Add(s.Substring(s.IndexOf(": ") + 1).Trim().Replace("\\.\\\\",""));
                       // //System.Windows.Forms.MessageBox.Show(results.Last());
                    }*/
                }
                        
                        // results.Add(await reader.ReadToEndAsync().ConfigureAwait(false));
                              //stream.Flush(); 
                 
                clam.Client.Dispose();
            }
            catch(Exception em)
            {
                //System.Windows.Forms.MessageBox.Show(em.ToString());
            }
            finally
            {
                /*if (clam.Connected)
                {
                    clam.Client.Dispose();
                }*/
            }




#if DEBUG
            stopWatch.Stop();
            System.Diagnostics.Debug.WriteLine("Command {0} took: {1}", commands[0], stopWatch.Elapsed);
#endif
            List<string> arRs = new List<string>();
            ClamScanResult[] rr = null;
            try
            {
                arRs = results.ToList();
                rr = Array.ConvertAll(arRs.ToArray(), item => new ClamScanResult(item));
            }
            catch (Exception ee)
            {
                //System.Windows.Forms.MessageBox.Show(ee.ToString());
            }
            ////System.Windows.Forms.MessageBox.Show(String.Join("\n",arRs));
            return rr;
        }

        /// <summary>
        /// Helper method to send a byte array over the wire to the ClamAV server, split up in chunks.
        /// </summary>
        /// <param name="sourceStream">The stream to send to the ClamAV server.</param>
        /// <param name="clamStream">The communication channel to the ClamAV server.</param>
        /// <param name="cancellationToken"></param>
        private async Task SendStreamFileChunksAsync(Stream sourceStream, Stream clamStream, CancellationToken cancellationToken)
        {
            var size = MaxChunkSize;
            var bytes = new byte[size];

            while ((size = await sourceStream.ReadAsync(bytes, 0, size, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (sourceStream.Position > MaxStreamSize)
                {
                    throw new MaxStreamSizeExceededException(MaxStreamSize);
                }

                var sizeBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(size));  //convert size to NetworkOrder!
                await clamStream.WriteAsync(sizeBytes, 0, sizeBytes.Length, cancellationToken).ConfigureAwait(false);
                await clamStream.WriteAsync(bytes, 0, size, cancellationToken).ConfigureAwait(false);
            }

            var newMessage = BitConverter.GetBytes(0);
            await clamStream.WriteAsync(newMessage, 0, newMessage.Length, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets the ClamAV server version
        /// </summary>
        public Task<string> GetVersionAsync()
        {
            return GetVersionAsync(CancellationToken.None);
        }

        /// <summary>
        /// Gets the ClamAV server version
        /// </summary>
        public async Task<string> GetVersionAsync(CancellationToken cancellationToken)
        {
            var version = await ExecuteClamCommandAsync("VERSION", cancellationToken).ConfigureAwait(false);

            return version;
        }

        /// <summary>
        /// Executes a PING command on the ClamAV server.
        /// </summary>
        /// <returns>If the server responds with PONG, returns true.  Otherwise returns false.</returns>
        public Task<bool> PingAsync()
        {
            return PingAsync(CancellationToken.None);
        }

        /// <summary>
        /// Executes a PING command on the ClamAV server.
        /// </summary>
        /// <returns>If the server responds with PONG, returns true.  Otherwise returns false.</returns>
        public async Task<bool> PingAsync(CancellationToken cancellationToken)
        {
            var result = await ExecuteClamCommandAsync("PING", cancellationToken).ConfigureAwait(false);
            return result.ToLowerInvariant() == "pong";
        }

        /// <summary>
        /// Scans a file/directory on the ClamAV Server.
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        public Task<ClamScanResult> ScanFileOnServerAsync(string filePath)
        {
            return ScanFileOnServerAsync(filePath, CancellationToken.None);
        }

        /// <summary>
        /// Scans a file/directory on the ClamAV Server.
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        public async Task<ClamScanResult> ScanFileOnServerAsync(string filePath, CancellationToken cancellationToken)
        {
            return new ClamScanResult(await ExecuteClamCommandAsync(String.Format("SCAN {0}", filePath), cancellationToken).ConfigureAwait(false));
        }

        /// <summary>
        /// Scans a file/directory on the ClamAV Server using multiple threads on the server.
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        public Task<ClamScanResult> ScanFileOnServerMultithreadedAsync(string filePath)
        {
            return ScanFileOnServerMultithreadedAsync(filePath, CancellationToken.None);
        }

        /// <summary>
        /// Scans a file/directory on the ClamAV Server using multiple threads on the server.
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        public async Task<ClamScanResult> ScanFileOnServerMultithreadedAsync(string filePath, CancellationToken cancellationToken)
        {
            return new ClamScanResult(await ExecuteClamCommandAsync(String.Format("MULTISCAN {0}", filePath), cancellationToken).ConfigureAwait(false));
        }


        public async Task<ClamScanResult[]> ScanFileOnServerMultithreadedAsync(string[] filePath, CancellationToken cancellationToken)
        {
            string[] cmds = new string[filePath.Length];
            for (int i = 0; i < cmds.Length; i++)
                cmds[i] = String.Format("SCAN {0}", filePath[i].TrimEnd('\n','\0', '\r', ' '));
            //List<ClamScanResult> list = new List<ClamScanResult>();
            
            var strs = await ExecuteClamCommandAsync(cmds, cancellationToken).ConfigureAwait(false);

           
           // list.Add(new ClamScanResult(strs[c]));*/
            return strs;
        }


        /// <summary>
        /// Sends the data to the ClamAV server as a stream.
        /// </summary>
        /// <param name="fileData">Byte array containing the data from a file.</param>
        /// <returns></returns>
        public Task<ClamScanResult> SendAndScanFileAsync(byte[] fileData)
        {
            return SendAndScanFileAsync(fileData, CancellationToken.None);
        }

        /// <summary>
        /// Sends the data to the ClamAV server as a stream.
        /// </summary>
        /// <param name="fileData">Byte array containing the data from a file.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns></returns>
        public async Task<ClamScanResult> SendAndScanFileAsync(byte[] fileData, CancellationToken cancellationToken)
        {
            var sourceStream = new MemoryStream(fileData);
            return new ClamScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(sourceStream, stream, token)).ConfigureAwait(false));
        }

        /// <summary>
        /// Sends the data to the ClamAV server as a stream.
        /// </summary>
        /// <param name="sourceStream">Stream containing the data to scan.</param>
        /// <returns></returns>
        public Task<ClamScanResult> SendAndScanFileAsync(Stream sourceStream)
        {
            return SendAndScanFileAsync(sourceStream, CancellationToken.None);
        }

        /// <summary>
        /// Sends the data to the ClamAV server as a stream.
        /// </summary>
        /// <param name="sourceStream">Stream containing the data to scan.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns></returns>
        public async Task<ClamScanResult> SendAndScanFileAsync(Stream sourceStream, CancellationToken cancellationToken)
        {
            return new ClamScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(sourceStream, stream, token)).ConfigureAwait(false));
        }

        /// <summary>
        /// Reads the file from the path and then sends it to the ClamAV server as a stream.
        /// </summary>
        /// <param name="filePath">Path to the file/directory.</param>
        public async Task<ClamScanResult> SendAndScanFileAsync(string filePath)
        {
            using (var stream = File.OpenRead(filePath))
            {
                return await SendAndScanFileAsync(stream).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Reads the file from the path and then sends it to the ClamAV server as a stream.
        /// </summary>
        /// <param name="filePath">Path to the file/directory.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        public async Task<ClamScanResult> SendAndScanFileAsync(string filePath, CancellationToken cancellationToken)
        {
            using (var stream = File.OpenRead(filePath))
            {
                return await SendAndScanFileAsync(stream, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}