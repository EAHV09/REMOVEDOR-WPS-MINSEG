using Microsoft.Win32;
using Minseg.Core;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Minseg.App;

internal static class Dialogs
{
    private static (Window Window,StackPanel Body,StackPanel Buttons) Create(Window owner,string title,string message)
    {
        var body=new StackPanel{Margin=new Thickness(22,20,22,12)};
        body.Children.Add(new TextBlock{Text=title,FontFamily=(FontFamily)Application.Current.Resources["TitleFont"],FontSize=24,Margin=new Thickness(0,0,0,12)});
        body.Children.Add(new TextBlock{Text=string.IsNullOrWhiteSpace(message)?"No se pudo completar este paso. Guarda el detalle para revisarlo.":message,TextWrapping=TextWrapping.Wrap});
        var buttons=new StackPanel{Orientation=Orientation.Horizontal,HorizontalAlignment=HorizontalAlignment.Right,Margin=new Thickness(22,12,22,18)};
        var panel=new DockPanel();DockPanel.SetDock(buttons,Dock.Bottom);panel.Children.Add(buttons);
        panel.Children.Add(new ScrollViewer{Content=body,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,MaxHeight=Math.Max(180,SystemParameters.WorkArea.Height-180)});
        var window=new Window{Owner=owner.IsVisible?owner:null,Title=title,Icon=owner.Icon,Width=Math.Min(580,SystemParameters.WorkArea.Width-30),SizeToContent=SizeToContent.Height,
            MaxHeight=SystemParameters.WorkArea.Height-40,ResizeMode=ResizeMode.NoResize,WindowStartupLocation=WindowStartupLocation.CenterOwner,Content=panel};
        return(window,body,buttons);
    }

    public static void Info(Window owner,string title,string message)
    {
        var (window,_,buttons)=Create(owner,title,message);
        var close=new Button{Content="Aceptar",IsDefault=true,IsCancel=true};ActionIcon.Apply(close,"Check");
        close.Click+=(_,_)=>window.Close();buttons.Children.Add(close);window.ShowDialog();
    }

    public static bool Confirm(Window owner,string title,string message)
    {
        var (window,_,buttons)=Create(owner,title,message);
        var cancel=new Button{Content="Cancelar",IsCancel=true};ActionIcon.Apply(cancel,"Cancel");
        var proceed=new Button{Content="Continuar",Style=(Style)Application.Current.Resources["Primary"]};ActionIcon.Apply(proceed,"Check");
        cancel.Click+=(_,_)=>window.DialogResult=false;proceed.Click+=(_,_)=>window.DialogResult=true;
        buttons.Children.Add(cancel);buttons.Children.Add(proceed);return window.ShowDialog()==true;
    }

    public static bool ConfirmRemoval(Window owner,IReadOnlySet<Product> products,string message,bool cleaning=false)
    {
        var (window,body,buttons)=Create(owner,cleaning?"Limpiar archivos":"Desinstalar",message);
        var checks=new List<CheckBox>();
        void Add(string text)
        {
            var check=new CheckBox{Content=new TextBlock{Text=text,TextWrapping=TextWrapping.Wrap},Margin=new Thickness(0,16,0,0)};
            checks.Add(check);body.Children.Add(check);
        }
        if(products.Contains(Product.Wps))Add("Ya guardé mis documentos y revisé los archivos de la nube de WPS.");
        if(products.Contains(Product.AnyDesk))Add("Estoy frente al equipo o tengo otro acceso que no depende de AnyDesk.");
        var cancel=new Button{Content="Cancelar",IsCancel=true};ActionIcon.Apply(cancel,"Cancel");cancel.Click+=(_,_)=>window.DialogResult=false;
        var proceed=new Button{Content=cleaning?"Limpiar":"Desinstalar",IsEnabled=false,Style=(Style)Application.Current.Resources["Primary"]};
        ActionIcon.Apply(proceed,"Trash");
        foreach(var check in checks){check.Checked+=(_,_)=>proceed.IsEnabled=checks.All(c=>c.IsChecked==true);check.Unchecked+=(_,_)=>proceed.IsEnabled=false;}
        proceed.Click+=(_,_)=>window.DialogResult=true;
        buttons.Children.Add(cancel);buttons.Children.Add(proceed);
        return window.ShowDialog()==true;
    }

    public static void Error(Window owner,Exception error,string operation)
    {
        var diagnostic=ErrorDetails.Diagnostic(error,operation);
        var (window,body,buttons)=Create(owner,"No se pudo completar",operation+"\n\n"+ErrorDetails.Message(error));
        body.Children.Add(new Expander{Header="Ver detalle del error",Margin=new Thickness(0,18,0,0),Content=new TextBox{Text=diagnostic,IsReadOnly=true,TextWrapping=TextWrapping.Wrap,MaxHeight=180,VerticalScrollBarVisibility=ScrollBarVisibility.Auto}});
        var result=new TextBlock{TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,12,0,0)};body.Children.Add(result);
        var save=new Button{Content="Guardar detalle"};ActionIcon.Apply(save,"Save");
        save.Click+=(_,_)=>
        {
            var dialog=new SaveFileDialog{Filter="Texto|*.txt",FileName="MINSEG-error-"+DateTime.Now.ToString("yyyyMMdd-HHmm")+".txt"};
            if(dialog.ShowDialog(window)!=true)return;
            try{File.WriteAllText(dialog.FileName,diagnostic);result.Text="Detalle guardado. Compártelo solo con el personal de soporte.";}
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException){result.Text="No se guardó: "+ErrorDetails.Message(ex);}
        };
        var close=new Button{Content="Aceptar",IsDefault=true,IsCancel=true};ActionIcon.Apply(close,"Check");close.Click+=(_,_)=>window.Close();
        buttons.Children.Add(save);buttons.Children.Add(close);window.ShowDialog();
    }
}
