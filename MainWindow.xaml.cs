using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using System.Numerics;
using System.Collections;
using Microsoft.Win32;

namespace myRsa
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>

    public class PublicKey
    {
        public PublicKey()
        {
            this.N = BigInteger.Parse("115835143529011985466946897371659768942707075251385995517214050122410566973563965811168663559614636580713282451012293945169200873869218782362296940822448735543079113463384249819134147369806470560382457164633045830912243978622870542174381898756721599280783431283777436949655777218920351233463535926738440504017");
            this.E = 65537;
        }
        public PublicKey(BigInteger N, BigInteger E)
        {
            this.N = N;
            this.E = E;
        }
        public BigInteger N { get; set; }
        public BigInteger E { get; set; }
        public override string ToString()
        {
            return "N = " + N.ToString() + " : E =" + E.ToString();
        }
    }
    public class PrivateKey
    {
        public PrivateKey()
        {
            this.N = 0;
            this.D = 0;
        }
        public BigInteger N { get; set; }
        public BigInteger D { get; set; }
        public override string ToString()
        {
            return "N = " + N.ToString() + " : D =" + D.ToString();
        }

    }

    public class Rsa
    {
        public PrivateKey myPrivateKey;
        public PublicKey myPublicKey;
        public PublicKey otherPublicKey;
        public BigInteger maxPrime = 100; // Constante utilisée dans le calcul, est universelle
        public Rsa()
        {
            this.myPublicKey = new PublicKey();
            this.myPrivateKey = new PrivateKey();
            this.otherPublicKey = this.myPublicKey;
        }

        public String cipher(String message)
        {
            String result = "";
            // Test if the key is not null
            if (this.otherPublicKey.E == 0 && this.otherPublicKey.N == 0)
            {
                return "!!! Other's public key empty, can't cipher !!!";
            }
            for (int i = 0; i < message.Length; i++)
            {
                BigInteger l = message[i];
                BigInteger n = BigInteger.ModPow(l, this.otherPublicKey.E, this.otherPublicKey.N);
                result += (char)n;
            }
            return result;
        }

        public BigInteger cipher_int(BigInteger message)
        {
            // Test if the key is not null
            if (this.otherPublicKey.E == 0 && this.otherPublicKey.N == 0)
            {
                return -1;
            }
            BigInteger n = BigInteger.ModPow(message, this.otherPublicKey.E, this.otherPublicKey.N);
            return n;
        }

        public String decipher(String message)
        {
            String result = "";
            // Test if the key is not null
            if (this.myPrivateKey.D == 0 && this.myPrivateKey.N == 0)
            {
                return "!!! Private key empty, can't decipher !!!";
            }
            for (int i = 0; i < message.Length; i++)
            {
                BigInteger m = message[i];
                BigInteger n = BigInteger.ModPow(m, this.myPrivateKey.D, this.otherPublicKey.N);
                result += (char)n;

            }
            return result;
        }

        public BigInteger decipher_int(BigInteger message)
        {
            // Test if the key is not null
            if (this.myPrivateKey.D == 0 && this.myPrivateKey.N == 0)
            {
                return -1;
            }
            BigInteger n = BigInteger.ModPow(message, this.myPrivateKey.D, this.otherPublicKey.N);
            return n;
        }

        public void gen_keys()
        {
            BigInteger[] keys = new BigInteger[2];
            List<BigInteger> primes = GeneratePrimes(maxPrime);
            var r1 = new Random();
            BigInteger p1 = primes[r1.Next(1, primes.Count - 1)];
            BigInteger p2 = primes[r1.Next(1, primes.Count - 1)];
            this.myPublicKey.N = this.myPrivateKey.N = p1 * p2;
            BigInteger phi = (p1 - 1) * (p2 - 1);
            do
            {
                this.myPublicKey.E = r1.Next(3, (int)phi);
            } while (GCD(this.myPublicKey.E, phi) != 1);
            //this.myPublicKey.E = 3;
            this.myPrivateKey.D = (int)modInverse(this.myPublicKey.E, phi);
        }

        // Generates a list of primes numbers in a given range
        public static List<BigInteger> GeneratePrimes(BigInteger n)
        {
            List<BigInteger> primes = new List<BigInteger>();
            primes.Add(2);
            BigInteger nextPrime = 3;
            while (primes[primes.Count - 1] < n)
            {
                BigInteger sqrt = Sqrt(nextPrime);
                bool isPrime = true;
                for (int i = 0; (BigInteger)primes[i] <= sqrt; i++)
                {
                    if (nextPrime % primes[i] == 0)
                    {
                        isPrime = false;
                        break;
                    }
                }
                if (isPrime)
                {
                    primes.Add(nextPrime);
                }
                nextPrime += 2;
            }
            return primes.GetRange(0, primes.Count - 2);
        }

        // Function for Greatest common divider calculus
        private static BigInteger GCD(BigInteger a, BigInteger b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            return a == 0 ? b : a;
        }

        // Function for modular multiplicative inverse calculus
        public static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }

        public static BigInteger Sqrt(BigInteger number)
        {
            if (number < 9)
            {
                if (number == 0)
                    return 0;
                if (number < 4)
                    return 1;
                else
                    return 2;
            }

            BigInteger n = 0, p = 0;
            var high = number >> 1;
            var low = BigInteger.Zero;

            while (high > low + 1)
            {
                n = (high + low) >> 1;
                p = n * n;
                if (number < p)
                {
                    high = n;
                }
                else if (number > p)
                {
                    low = n;
                }
                else
                {
                    break;
                }
            }
            return number == p ? n : low;
        }
    }

    public partial class MainWindow : Window
    {
        Rsa myRsa = new Rsa();

        public MainWindow()
        {
            //InitializeComponent();
        }
        private void call_cipher(object sender, RoutedEventArgs e)
        {

            this.myRsa.otherPublicKey = new PublicKey(int.Parse(tbOtherPkN.Text), int.Parse(tbOtherPkE.Text));
            tbMsgDecipher.Text = this.myRsa.cipher(tbMsgCipher.Text);
        }
        private void call_decipher(object sender, RoutedEventArgs e)
        {
            tbMsgCipher.Text = this.myRsa.decipher(tbMsgDecipher.Text);
        }
        private void stackPanel_Loaded(object sender, RoutedEventArgs e)
        {
            lbPrivKey.Content = this.myRsa.myPrivateKey.ToString();
            lbPubKey.Content = this.myRsa.myPublicKey.ToString();
            /*
             * Pour le challenge FCSC SMIC 1
            BigInteger c = BigInteger.Parse("63775417045544543594281416329767355155835033510382720735973");
            BigInteger text = this.myRsa.cipher_int(c);
            tbMsgCipher.Text = text.ToString();
            */
            BigInteger m = BigInteger.Parse("29092715682136811148741896992216382887663205723233009270907036164616385404410946789697601633832261873953783070225717396137755866976801871184236363551686364362312702985660271388900637527644505521559662128091418418029535347788018938016105431888876506254626085450904980887492319714444847439547681555866496873380");
            BigInteger text = this.myRsa.cipher_int(m);
            tbMsgDecipher.Text = text.ToString();
        }

        private void generate_keys(object sender, RoutedEventArgs e)
        {
            this.myRsa.gen_keys();
            lbPrivKey.Content = this.myRsa.myPrivateKey.ToString();
            lbPubKey.Content = this.myRsa.myPublicKey.ToString();
        }
        private void saveInFile(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.ShowDialog();
            System.IO.File.WriteAllText(openFileDialog1.FileName, tbMsgDecipher.Text);
        }
        private void readFromFileCipher(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            bool? dr = openFileDialog1.ShowDialog();
            if (dr == true)
                tbMsgCipher.Text = System.IO.File.ReadAllText(openFileDialog1.FileName);
        }
        private void readFromFileDecipher(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.ShowDialog();
            bool? dr = openFileDialog1.ShowDialog();
            if (dr == true)
                tbMsgDecipher.Text = System.IO.File.ReadAllText(openFileDialog1.FileName);
        }
        
    }
}
