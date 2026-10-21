using System.Windows;
using System.Windows.Media;
namespace Minseg.App;

public static class AppTheme
{
    public static bool IsDark{get;private set;}=true;
    public static void Apply(bool dark)
    {
        IsDark=dark;
        void Set(string key,string light,string night)=>Application.Current.Resources[key]=new SolidColorBrush((Color)ColorConverter.ConvertFromString(dark?night:light));
        Set("Canvas","#F2F4F7","#000000");Set("Ink","#172333","#F4F7FB");Set("Subtle","#4E5D70","#C8C8C8");
        Set("Surface","#FFFFFF","#0C0C0C");Set("Raised","#E8EEF5","#101010");Set("Input","#FFFFFF","#0D0D0D");
        Set("Edge","#C4CFDC","#333333");Set("StrongEdge","#8192A6","#646464");Set("Hover","#DAE5F0","#242424");
        Set("Track","#E8EEF5","#050505");Set("Thumb","#8192A6","#666666");Set("PolicyPanel","#F3EDFD","#151515");
        Set("Wps","#006579","#22D3F5");Set("AnyDesk","#A44200","#FF923F");Set("Blocking","#6332A1","#BF9BFF");Set("Office","#086B4E","#42E2AD");
        Set("WpsFill","#22D3F5","#22D3F5");Set("AnyDeskFill","#FF923F","#FF923F");Set("BlockingFill","#BF9BFF","#BF9BFF");Set("OfficeFill","#42E2AD","#42E2AD");
        Set("Header","#B3152C","#B3152C");Set("Warning","#8A4C00","#FFD24A");
    }
}
