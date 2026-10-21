using System.Windows;
using System.Reflection;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Minseg.Core;
namespace Minseg.App;
public partial class App:Application
{
    private readonly bool renderOnly;
    public App():this(false) { }
    internal App(bool renderOnly){this.renderOnly=renderOnly;}
    protected override void OnStartup(StartupEventArgs e)
    {
        if(renderOnly)return;
        // Only the explicitly requested WPS operation is exposed by this edition.
        if(e.Args.Length>0&&!e.Args.SequenceEqual(new[]{"--check-package"})&&!e.Args.SequenceEqual(new[]{"--prepare-office"})
            &&!e.Args.SequenceEqual(new[]{"--remove-machine","wps"})){Shutdown(64);return;}
        var officeCommand=OfficeAutomation.Parse(e.Args);
        if(officeCommand!=OfficeCommand.None)
        {
            // No StartupUri is assigned: only the interactive branch below creates a visible window.
            if(officeCommand==OfficeCommand.Invalid){Shutdown(64);return;}
            if(!DeviceInventory.IsAdministrator){Shutdown(5);return;}
            SecureWorkspace? journal=null;
            try
            {
                journal=new SecureWorkspace();
                var device=DeviceInventory.Read();var plan=OfficeRecovery.Read(device);
                var result=OfficePolicy.Prepare(device,plan,journal);
                journal.Log(null,"Office automático",result.Path,result.AppliesAtSignIn?"Pendiente de inicio de sesión":"Preparado para TI",result.Message);
                Shutdown(result.ExitCode);
            }
            catch(Exception ex)
            {
                try{journal?.Log(null,"Office automático","Office","Pendiente",ErrorDetails.Message(ex));}catch{ }
                Shutdown(20);
            }
            finally{journal?.Dispose();}
            return;
        }
        AppTheme.Apply(true);
        if(e.Args.SequenceEqual(new[]{"--check-package"}))
        {
            try
            {
                _=new MainWindow();
                foreach(var name in new[]{"minseg-seal.png","minseg-wordmark.png","cibercom.png","app.ico"})
                {
                    var bitmap=new BitmapImage(new Uri("pack://application:,,,/MINSEG-Control;component/Assets/"+name));
                    if(bitmap.PixelWidth==0)throw new InvalidOperationException("Falta un logo.");
                }
                if(Fonts.GetFontFamilies(new Uri("pack://application:,,,/MINSEG-Control;component/Assets/")).Count<2)throw new InvalidOperationException("Faltan fuentes.");
                using var guide=Assembly.GetExecutingAssembly().GetManifestResourceStream("Minseg.App.Help.Guia")??throw new InvalidOperationException("Falta la ayuda.");
                using var officeGuide=Assembly.GetExecutingAssembly().GetManifestResourceStream("Minseg.App.Help.Office")??throw new InvalidOperationException("Falta la guía de Office para TI.");
                _=PolicyBuilder.Create(true,1);
                AppLockerPolicy.Validate(AppLockerPolicy.Create(true));
                using var appLocker=typeof(AppLockerPolicy).Assembly.GetManifestResourceStream("Minseg.Core.AppLockerHost.ps1")??throw new InvalidOperationException("Falta AppLocker.");
                Shutdown(0);
            }
            catch{Shutdown(2);}
            return;
        }
        DispatcherUnhandledException+=(_,args)=>
        {
            if(MainWindow!=null)Dialogs.Error(MainWindow,args.Exception,"Ocurrió un error inesperado. Si hay un desinstalador abierto, revisa sus pasos. Después esta ventana se cerrará.");
            else MessageBox.Show("No se pudo abrir la ventana.\n\n"+ErrorDetails.Message(args.Exception),"REMOVEDOR DEL WPS MINSEG",MessageBoxButton.OK,MessageBoxImage.Error);
            args.Handled=true;
            Shutdown(1);
        };
        base.OnStartup(e);
        MainWindow=new MainWindow();MainWindow.Show();
    }
}
