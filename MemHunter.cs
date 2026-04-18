// MemHunter — portable Streamlit launcher (no console).
//
// Build (cmd.exe), from the folder containing this file:
//   "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:winexe /win32icon:assets\memhunter_logo.ico /out:MemHunter.exe MemHunter.cs
//
// Icon file: place your logo as `assets\memhunter_logo.ico` (multi-size .ico recommended).
// In-app logo: same art as `assets\memhunter_logo.png` (transparent PNG from Canva is fine).
//
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        string baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        if (string.IsNullOrEmpty(baseDir))
            return 1;

        Directory.SetCurrentDirectory(baseDir);

        string py = Path.Combine(baseDir, "python_env", "python.exe");
        if (!File.Exists(py))
        {
            return 2;
        }

        string appPy = Path.Combine(baseDir, "app.py");
        if (!File.Exists(appPy))
        {
            return 3;
        }

        string sitePackages = Path.Combine(baseDir, "python_env", "Lib", "site-packages");

        var psi = new ProcessStartInfo
        {
            FileName = py,
            Arguments = "-m streamlit run app.py --server.headless true --server.port 8501",
            WorkingDirectory = baseDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        psi.EnvironmentVariables["PYTHONPATH"] = sitePackages;

        try
        {
            using (Process proc = Process.Start(psi))
            {
                if (proc == null)
                    return 4;

                Thread.Sleep(2000);
                Process.Start(
                    new ProcessStartInfo
                    {
                        FileName = "http://localhost:8501",
                        UseShellExecute = true,
                    });
            }
        }
        catch
        {
            return 5;
        }

        return 0;
    }
}
