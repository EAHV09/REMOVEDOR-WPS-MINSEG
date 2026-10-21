# Verificación de la interfaz WPS 3.1.1

Comprobaciones locales del 21 de octubre de 2026:

- Compilación con .NET SDK 10.0.401 y runtime 10.0.12, dependencias bloqueadas y auditoría de NuGet sin avisos.
- Núcleo: 237 pruebas correctas; una prueba de enlaces simbólicos omitida por privilegios del entorno.
- Estado de políticas: 14 pruebas con archivos de ejemplo. No aplican políticas al equipo.
- Interfaz: ocho vistas WPF con datos ficticios, modos negro/claro, tamaño reducido, búsqueda en curso, opciones abiertas y resultado pendiente.
- Revisión visual: MINSEG.gob.pa centrado encima del título; escudo de 124 píxeles; logos proporcionales, botones y texto legibles.
- El núcleo conserva los mismos bytes que la fuente pública 3.1.0. Los cambios de aplicación afectan a la presentación y al número mostrado en Ayuda.

La comprobación segura del paquete está diseñada para verificar los recursos incluidos y el rechazo de argumentos inválidos, sin desinstalar ni preparar Office. En el candidato intermedio pasó sus cinco comprobaciones. Tras corregir el número de versión de Ayuda y volver a compilar, **Windows bloqueó el inicio del EXE final mediante Control de aplicaciones**. Por tanto, las cinco comprobaciones de apertura del archivo final quedan pendientes; no se atribuye a este archivo el resultado del candidato anterior. No se cambió ninguna protección para ejecutarlo.

Metadatos del EXE final: producto `REMOVEDOR DEL WPS MINSEG`, versión `3.1.1`, firma `NotSigned`. SHA-256: `62C9F2825FFAAE28B5683709BF3575D961626FAF4AA0302C05EB4AE31E3B57B6`.

**Límites:** estas comprobaciones no sustituyen una prueba real de WPS, persistencia, documentos u Office en las PC de MINSEG. No verifican todos los escalados DPI ni configuraciones de Windows 10/11. El candidato permanece sin firma Authenticode; la aceptación de SignPath, la compilación con origen verificable en GitHub, la firma y el piloto siguen pendientes.

El EXE se entrega separado de las fuentes. No se deben publicar inventarios, informes ni datos reales de los equipos.
