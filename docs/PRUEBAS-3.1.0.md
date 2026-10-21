# Verificación de la interfaz WPS 3.1.0

20 de octubre de 2026. Candidato local de Windows x64.

- Compilación Release y publicación autónoma correctas, sin advertencias ni errores.
- Núcleo: 237 pruebas correctas, 0 fallidas y 1 omitida por necesitar privilegio para crear enlaces simbólicos. El primer intento no pudo conectar el ejecutor de pruebas con su proceso auxiliar; la repetición con comunicación local permitida terminó correctamente.
- Interfaz WPF: ocho vistas renderizadas con datos ficticios. Comprobados negro puro y modo claro, cambio de tema, límites de los controles en dos tamaños, opciones plegadas, recursos incluidos, bloqueo de botones durante operaciones y errores Office separados del resultado de limpieza.
- Regresión de alcance: una instalación detectada en otra cuenta y sus advertencias se conservan en el resumen. Los resultados y las acciones de esta edición se limitan a WPS.
- Revisión independiente: corregidas dos omisiones en el nuevo escaneo relacionadas con inventario de otros perfiles y sus rutas personalizadas. Sin otros hallazgos en el cambio revisado.
- Los 49 archivos del núcleo permanecen iguales a la base 1.6.0. Esta revisión no es una nueva auditoría completa de ese núcleo.
- Paquete: el modo de comprobación de recursos sale con código 0. Argumentos desconocidos, producto AnyDesk y selección de ambos productos se rechazan con código 64.
- El EXE original adjunto conserva SHA-256 `3A2F8BFCD71D39B274C7446D20ED39FA4D741DD38EEA5A0AC71CB6BF011DFE1C`.

No se ejecutó una desinstalación real ni se cambiaron asociaciones, servicios, políticas de seguridad o el dominio. Las capturas no son resultados de un escaneo del equipo.

Pendientes: firma Authenticode, auditoría de dependencias en línea y piloto real en Windows 10/11 con las versiones instaladas de WPS, Office y Bitdefender. El EXE sin firma todavía puede ser bloqueado por Windows.

Actualización del 21 de octubre: la preparación pública completó la comprobación de dependencias en línea y repitió la compilación y pruebas. Véase [validación de la preparación pública](signpath/VALIDACION-3.1.0.md). La firma y el piloto real siguen pendientes.

Esta edición se centra en WPS. La entrega conjunta WPS/AnyDesk 1.6.0 se conserva aparte.
