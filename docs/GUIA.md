# REMOVEDOR DEL WPS MINSEG 3.1.0

## Uso

1. Abre el EXE. Lee el nombre del equipo y comprueba si WPS está registrado.
2. Pulsa **Escanear equipo** para buscar archivos y persistencia en las rutas habituales de WPS y los perfiles registrados. Esta acción no desinstala ni limpia.
3. Guarda los documentos abiertos y pulsa **Desinstalar WPS**. El programa comprueba el desinstalador, lo abre, limpia restos comprobados y verifica el resultado. Windows puede pedir permisos y el fabricante puede mostrar su asistente.
4. Lee el resultado en la misma pantalla. **Pendiente**, **Escaneo parcial** y **Sin instalación registrada** no significan que todo esté limpio. Si faltaron permisos o hubo un fallo, consulta el detalle.
5. **Guardar informe** exporta el resultado. Contiene datos del equipo: compártelo con personal autorizado.

El modo negro abre por defecto. **Modo claro / Modo oscuro** cambia los colores. Los tres logos, el icono WPS, las fuentes, .NET y esta ayuda están incluidos en el EXE. No necesitas instalar Python ni copiar el código fuente.

## Opciones avanzadas

- **Actualizar detección:** relee instalaciones, persistencia y Office.
- **Abrir como administrador:** solicita los permisos normales de Windows.
- **Ver restos y persistencia:** muestra rutas, confianza y alcance del escaneo.
- **Microsoft Office:** pulsa **Comprobar Office** y después usa la preparación automática en dominio o la selección de Windows en equipos independientes. El XML de cada PC depende de su Office instalado. La GPO lo aplica en el siguiente inicio de sesión; después hay que verificarlo. La sección Office para TI contiene los pasos.
- **Información del equipo:** equipo, usuario, Windows, IP, MAC y departamento editable.
- **Informe y respaldos:** resultado completo y registros de esta sesión. Los respaldos se guardan en MINSEG-Control dentro de ProgramData (administrador) o AppData local (usuario).

## Qué se conserva

Los documentos, archivos de recuperación, la nube WPSDrive/OneDrive y coincidencias dudosas se conservan. KingsoftData se revisa por componentes técnicos comprobados; no se borra como una carpeta completa. Por eso algunas carpetas con datos personales pueden permanecer.

No se fuerzan cierres de sesión, reinicios ni cierres de Explorer, Copilot u otros programas. Los asistentes del fabricante pueden tener sus propios pasos. Archivos ocupados, perfiles inaccesibles e instalaciones de otras cuentas pueden quedar pendientes.

El escaneo tiene límites de tiempo y archivos y no equivale a un análisis completo de malware. Se muestran sus límites en el informe. Esta edición realiza acciones solo sobre WPS. La versión conjunta con AnyDesk es una entrega separada.

## Firma y licencia

Este EXE aún no tiene firma Authenticode. Un cambio de interfaz o icono no elimina el bloqueo de Windows. La firma y el piloto en las PC de MINSEG siguen pendientes. No desactives Smart App Control ni Bitdefender para probarlo.

Código bajo Apache License 2.0. Logos y marcas conservan sus derechos. La licencia no es una firma digital.
