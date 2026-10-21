using System.Windows;
using System.Windows.Media;
namespace Minseg.App;

public static class ActionIcon
{
    public static readonly DependencyProperty DataProperty=DependencyProperty.RegisterAttached("Data",typeof(Geometry),typeof(ActionIcon));
    public static Geometry? GetData(DependencyObject target)=>(Geometry?)target.GetValue(DataProperty);
    public static void SetData(DependencyObject target,Geometry? value)=>target.SetValue(DataProperty,value);
    internal static void Apply(DependencyObject target,string key)=>SetData(target,(Geometry)Application.Current.Resources[key+"Icon"]);
}
