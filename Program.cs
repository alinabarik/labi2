using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

string hostname = null;
string ip = null;
bool isValid = false;
do
{
    Console.Write("tracert ");
    ip = Console.ReadLine();
    if (IPAddress.TryParse(ip, out _))
    {
        isValid = true;
        hostname = Dns.GetHostEntry(IPAddress.Parse(ip)).HostName;
    }
    else
    {
        try
        {
            IPHostEntry host = Dns.GetHostEntry(ip);
            IPAddress[] addresses = host.AddressList;
            if (addresses.Length > 0)
            {
                hostname = ip;
                ip = addresses[0].ToString();
                isValid = true;
            }
            else Console.WriteLine("Для данного домена нет ipv4 aдреса. Попробуйте снова:");

        }
        catch (SocketException)
        {
            Console.WriteLine("Проверьте корректность ввода:");
        }
    }

} while (!isValid);


using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp))
{
    IPAddress dest = IPAddress.Parse(ip);
    EndPoint point = new IPEndPoint(dest,0);
    ICMPacket packet = new ICMPacket()
    {
        type = 8,
        code = 0,
        identifier = 1,
        seqnum = 1,
        data = new byte[32]
    };
    bool target = false;
    socket.ReceiveTimeout = 4000;
    Console.WriteLine($"\nТрассировка маршрута к {hostname} [{ip}]\nс максимальным числом прыжков 30:\n");

    for (int ttl = 1; ttl <= 30; ttl++)
        {

        IPAddress Hop=null;
        long[] time = new long[3];


        for (int p = 0; p < 3; p++)
            {
                packet.seqnum = (ushort)((ttl - 1) * 3 + p);
                packet.checksum = 0;
                packet.checksum = packet.ComputeCheckSum(packet.GetBytes());
                socket.Ttl = (short)ttl;

                EndPoint senderEP = new IPEndPoint(IPAddress.Any, 0);
                byte[] buffer = new byte[1024];
                Stopwatch stopwatch = new Stopwatch();

                try
                {
                    stopwatch.Start();
                    socket.SendTo(packet.GetBytes(), point);
                    int answ = socket.ReceiveFrom(buffer, ref senderEP);
                    stopwatch.Stop();

                    if (answ >= 28)
                    {
                    if (buffer[20] == 0 || buffer[20] == 11 || buffer[20] == 3)
                    {
                        Hop = ((IPEndPoint)senderEP).Address;
                        time[p] = stopwatch.ElapsedMilliseconds;
                    }
                    if(buffer[20] == 0)
                    {
                        target = true;
                    }

                    }
                }
                catch (SocketException ex)
                {
                if (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    stopwatch.Stop();
                    time[p] = -1;
                }
                }

        }
        Console.Write($"{ttl,4}\t");
        foreach (long i in time)
        {
            if (i >= 0)
                Console.Write($"{i,4} ms\t");
            else
                Console.Write("   *\t");
        }
        if (Hop == null)
            Console.WriteLine(" Превышен интервал ожидания для запроса.");
        else
        {
            try
            {
                Console.WriteLine(" "+Dns.GetHostEntry(Hop).HostName + " [" + Hop+"]");
            }
            catch(SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
            {
                Console.WriteLine(" "+Hop);
            }
        }

        if (target)
        {
            Console.WriteLine("\nТрассировка завершена.");
            break;
        }
    }
    socket.Close();
}
    



public class ICMPacket // класс пакета
{
    public byte type;
    public byte code;
    public ushort checksum;
    public ushort identifier;
    public ushort seqnum;
    public byte[] data;

    public byte[] GetBytes()// перевод полей класса в массив байтов(ведь именно массив мы и отправляем)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write(type);
                bw.Write(code);
                bw.Write(IPAddress.HostToNetworkOrder((short)checksum));
                bw.Write(IPAddress.HostToNetworkOrder((short)identifier));
                bw.Write(IPAddress.HostToNetworkOrder((short)seqnum));
                if (data!=null) bw.Write(data);
                return ms.ToArray();
            }
        }

    }
    public ushort ComputeCheckSum(byte[] data)// подсчет контрольной суммы
    {
        long sum = 0;// контрольная сумма в начале всегда обнуляется

        for(int i = 0; i < data.Length-1; i += 2)// переходим к скбадывания пар байтов
        {
            sum += (ushort)((data[i] << 8) | data[i + 1]);//сдвигаем первый байт на 8 бит(он становится старшим) и применяем логическое или с следующим байтом(младшим)  и прибавляем к сумме

        }

        if (data.Length % 2 != 0)// если количество байтов нечетное обрабатываем этот байт как старший
        {
            sum += (ushort)(data[data.Length - 1] << 8);
        }

        while ((sum >> 16)!=0)// если сумма выходит за размер 16 бит, то передний байт сдвигаем и прибавляем в гонец
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (ushort)~sum;// записываем перевернутую контрольную сумму(согласно стандарту icmp)
    }
}


