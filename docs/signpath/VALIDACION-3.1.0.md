# Preparación pública de 3.1.0

Comprobaciones locales realizadas el 21 de octubre de 2026 para preparar este repositorio. No son un piloto de desinstalación en una PC de MINSEG.

- Los 74 archivos de aplicación y recursos en `src` conservan los mismos bytes que las fuentes de la entrega 3.1.0. Los cambios de esta preparación afectan a documentación y compilación/firma.
- Restauración bloqueada y consulta de vulnerabilidades de NuGet completadas para aplicación, pruebas y prueba visual, sin avisos de vulnerabilidades en esas restauraciones. La comprobación debe repetirse en cada compilación; no sustituye una auditoría del código o del runtime.
- 237 pruebas del núcleo correctas, 0 fallidas y 1 omitida por necesitar permiso para crear enlaces simbólicos.
- 14 pruebas de estado del núcleo compartido correctas, sin cambiar servicios ni políticas del equipo.
- 8 vistas WPF y comprobaciones de interfaz correctas con datos ficticios.
- Publicación de un único EXE autónomo. Comprobación de recursos con salida 0; argumentos inválidos y operaciones de AnyDesk/ambos rechazados con salida 64.
- Revisión de patrones de credenciales y datos privados sin coincidencias en los archivos publicables examinados; enlaces locales, XML y YAML comprobados. La revisión no garantiza ausencia de cualquier secreto.
- Revisión independiente de esta preparación sin hallazgos P1/P2 pendientes. El código del motor no se ha vuelto a auditar de forma completa.

Los fallos iniciales de conexión y caché de NuGet se resolvieron antes de completar la compilación estricta. Una ejecución con temporales dentro de Documentos fue rechazada por la protección de archivos personales; las pruebas completas terminaron usando el directorio temporal normal, sin modificar esa protección.

El candidato generado sigue **sin firma**. La compilación en GitHub, aceptación de SignPath, firmas reales y piloto con WPS/Office/Bitdefender deben verificarse por separado. No se ejecutaron desinstaladores ni se cambiaron asociaciones de archivos durante estas comprobaciones.

El repositorio contiene fuentes, recursos y herramientas de compilación. El EXE se entrega como archivo independiente y el ZIP de fuentes se distribuye aparte.
