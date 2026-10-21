# Interfaz WPS 3.1.0

Edición centrada en WPS que aplica el diseño aprobado para el programa original «WPS_Remover_MINSEG v3 DEFINITIVO».

- Fondo negro al abrir y botón para cambiar a modo claro.
- Encabezado rojo, los tres logos originales transparentes y el icono WPS en la ventana y el EXE.
- Pantalla única: Escanear equipo, Desinstalar WPS, resultado e informe.
- Opciones avanzadas plegadas: Office, detalle de hallazgos, equipo y respaldos.
- Dos fuentes incluidas: Barlow y Source Sans 3.
- Al abrir solo se lee la información del equipo y las instalaciones registradas. El recorrido de archivos comienza al pulsar Escanear.
- El escaneo dirigido utiliza las rutas WPS de los perfiles registrados, con avisos de acceso, tiempo y alcance.
- No se muestran ni se aceptan operaciones de AnyDesk en esta edición. La versión conjunta 1.6.0 permanece separada.

## Base técnica y protección de datos

El PS1 original contenía cierre de Explorer, cambios recursivos de permisos y borrado completo de KingsoftData/WPSDrive. Esas operaciones no se incorporan. Esta edición reutiliza el núcleo de limpieza de MINSEG 1.6.0 sin modificarlo y le añade la interfaz WPS aprobada. Los originales no se sobrescriben.

La limpieza comprueba identidad y destino, conserva documentos, la nube y coincidencias dudosas, y registra los pendientes. No garantiza eliminación completa en cualquier equipo. Los desinstaladores del fabricante pueden abrir sus propios asistentes. Windows conserva UAC y sus controles de ejecución.

Office se verifica y configura aparte. En dominio prepara el XML de las aplicaciones detectadas para una política compatible y el siguiente inicio de sesión. En PC independientes se usa la selección admitida de Windows. No modifica hashes UserChoice.

## Entrega y pruebas

Un EXE autónomo x64 con imágenes, fuentes, .NET, ayuda y licencias. Código fuente separado bajo Apache 2.0; los logos conservan sus derechos.

La compilación no tiene firma Authenticode. La firma con SignPath y las pruebas reales en los equipos de MINSEG siguen pendientes. El cambio visual no resuelve el bloqueo por Smart App Control.

Las pruebas de interfaz usan datos ficticios y no ejecutan desinstaladores ni cambian asociaciones o políticas del equipo de desarrollo. La auditoría de dependencias en línea no se realiza en esta compilación sin red.
