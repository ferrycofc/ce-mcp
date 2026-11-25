using System;
using System.Diagnostics;

namespace CeMcpFixture {
  public class Sample {
    public static int Counter = 123;
    public int Health = 456;
    public float Ratio = 1.5f;
    public int Add(int value) { return Health + value; }
  }
  public class Program {
    private static Sample KeepAlive = new Sample();
    public static void Main() {
      Console.WriteLine(Process.GetCurrentProcess().Id);
      Console.Out.Flush();
      while (Console.ReadLine() != "exit") { Console.WriteLine(KeepAlive.Add(1)); Console.Out.Flush(); }
    }
  }
}
