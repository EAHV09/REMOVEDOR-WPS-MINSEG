# Office automático en MINSEG — Windows 10 y 11

La versión 1.6.0 prepara las asociaciones con el Office de **cada PC**. No hace falta usar una PC como plantilla ni asignar Word, Excel y PowerPoint por separado. Windows aplica la política al próximo inicio de sesión; preparar el XML no significa que los predeterminados ya hayan cambiado.

## Qué detecta

Lee las aplicaciones registradas en las vistas de registro de 32 y 64 bits, verifica la firma Microsoft y el ejecutable de apertura y muestra su versión de archivo. Genera los ProgID que realmente están registrados, sin deducirlos de la edición comercial. Office 2016, 2019, 2021, 2024 y Microsoft 365 pueden compartir números 16.0: no se adivina el nombre comercial con ese número.

Incluye los formatos admitidos y registrados de Word, Excel, PowerPoint, Outlook clásico, Access, OneNote de escritorio, Publisher, Visio y Project cuando estén instalados. La lista exacta se ve en **Ver formatos y programa de apertura** y en el XML. No instala aplicaciones que falten, no cambia PDF ni navegadores, y no cubre clientes web, el nuevo Outlook ni registros de aplicaciones empaquetadas. Una instalación por usuario sin registro de equipo necesita revisión por TI.

Si hay registros rotos, una firma no comprobada o dos instalaciones que compiten por el mismo formato, informa de detección parcial y conserva la configuración previa. TI debe reparar el registro de Office o resolver la instalación duplicada antes de reintentar. Detectar una versión no certifica su soporte o licencia.

## Probar una PC del dominio

1. Usa una PC Windows 10 y otra Windows 11 del dominio, con Office instalado, en un grupo piloto. Usa documentos de prueba guardados.
2. Abre el EXE autorizado por TI y pulsa **Preparar Office automático**. Si hace falta, Windows solicitará administrador. Después de desinstalar WPS, esta preparación también se intenta automáticamente.
3. Sin una política de asociaciones previa, la herramienta crea una política local propia para el siguiente inicio de sesión. Si ya hay otra GPO o MDM, solo prepara el XML para integración: no reemplaza esa política.
4. Guarda el trabajo y cierra e inicia sesión cuando lo decida el usuario. La herramienta no fuerza el cierre. Comprueba que el dominio no haya reemplazado la política local por otra.
5. Abre el removedor como el usuario afectado y pulsa **Comprobar Office**. Debe mostrar asociaciones y destinos de apertura Office comprobados. Abre una copia de un documento por aplicación. Si el icono sigue blanco pero abre bien, ese caso requiere revisión de la caché o de la instalación de Office.

## Una GPO para equipos con Office distintos

Cada PC prepara su propio archivo en:

```text
%ProgramData%\MINSEG-OfficeDefaults\Office-detectado.xml
```

La ruta concreta habitual es `C:\ProgramData\MINSEG-OfficeDefaults\Office-detectado.xml`. El botón y el informe indican la ruta utilizada. Si ProgramData está en otro disco, TI debe usar esa ruta real y separar el grupo de aplicación de la política. No se presupone que el campo de la GPO expanda variables de entorno.

TI debe revisar primero si hay una política existente. Windows tiene un único valor de configuración de asociaciones; si esa política también define PDF, navegador u otras aplicaciones, hay que integrar los formatos de Office en el proceso de TI y mantener esas otras asociaciones. El removedor conserva la política ajena y entrega el XML de Office; no realiza esa mezcla automáticamente.

En un grupo piloto sin otra política de asociaciones:

1. Distribuye el EXE firmado o autorizado por el procedimiento de MINSEG a una carpeta local protegida, por ejemplo `C:\Program Files\MINSEG\REMOVEDOR DEL WPS MINSEG.exe`. No concedas escritura a usuarios normales sobre el EXE, su carpeta o los XML.
2. Ejecuta como administrador o SYSTEM:

   ```powershell
   $officeRun = Start-Process -FilePath 'C:\Program Files\MINSEG\REMOVEDOR DEL WPS MINSEG.exe' -ArgumentList '--prepare-office' -WindowStyle Hidden -Wait -PassThru
   $officeRun.ExitCode
   ```

   El argumento es único y no admite rutas ni órdenes adicionales. En un script de despliegue, espera la terminación del proceso y recoge su código de salida. No se ejecutan escaneos WPS/AnyDesk ni desinstaladores con este argumento.

3. Comprueba que existe el XML propio de cada PC. En Administración de directivas de grupo, configura para el piloto: **Configuración del equipo → Plantillas administrativas → Componentes de Windows → Explorador de archivos → Establecer un archivo de configuración de asociaciones predeterminadas**. Habilita la opción y escribe la ruta local absoluta del XML.
4. Para actualizar la detección después de un cambio de Office, TI puede ejecutar el mismo EXE con `--prepare-office` como script de inicio de equipo o como parte del despliegue de Office, bajo SYSTEM. Configura el despliegue para esperar su finalización antes del inicio de sesión donde se quiera aplicar. No se garantiza ese orden con scripts asíncronos; el piloto debe comprobarlo. El removedor no instala tareas ni servicios residentes.
5. Una vez aplicada la GPO que apunta a ese archivo, el EXE actualiza únicamente su XML local y conserva el enlace de la GPO. No hay un XML único copiado desde otro Office. Si Office no cambió, el contenido permanece igual.
6. Comprueba el resultado de directivas y el siguiente inicio de sesión con una cuenta normal. Con la política habilitada Windows puede volver a aplicar estas asociaciones en cada inicio de sesión. En Windows 11 no se usan atributos opcionales exclusivos de versiones recientes: el XML mantiene el formato común de Windows 10/11.

Si coexisten MDM y GPO, TI debe revisar cuál es efectiva; MDM puede tener prioridad. Preparar un XML nunca elimina esa administración. En PC que no estén unidas al dominio, la configuración local de política no se presenta como automatización válida para usuarios existentes: permanece el flujo admitido de selección en Windows.

## Resultado de --prepare-office

| Código | Significado |
|---|---|
| 0 | Configuración preparada y política propia o enlace GPO compatible detectado. Pendiente del inicio de sesión y comprobación real. |
| 10 | XML preparado, pero TI debe integrarlo: política ajena/MDM o equipo fuera del dominio. |
| 5 | Faltan permisos de administrador. |
| 20 | No se pudo preparar: Office ausente, detección parcial, cambios concurrentes, archivo ajeno, permisos o error de escritura. Revisar informe. |
| 64 | Argumentos no admitidos. |

Los informes de la preparación elevada se guardan por sesión en `%ProgramData%\MINSEG-Control\...\acciones.jsonl`. Si ni siquiera se puede crear la carpeta protegida, puede no existir informe; el código 20 sigue indicando fallo. Las copias anteriores de XML quedan en `MINSEG-OfficeDefaults`. Solo administradores y SYSTEM pueden escribir; los usuarios pueden leer para que Windows aplique la configuración. No se reemplaza un XML previo cuyo propietario lógico/hash no pueda comprobarse.

## Recuperación y límites

**Opciones de Office → Desactivar política de Office** solo elimina el enlace de una política propia intacta. Conserva XML y asociaciones actuales. Una GPO de TI se desactiva desde TI, no desde ese botón. No se borran documentos ni se manipulan UserChoice, su hash o UCPD. No se cierra Explorer ni se apagan controles de seguridad.

Esta entrega sigue sin firma Authenticode. Preparar asociaciones no resuelve el bloqueo del EXE por Smart App Control. La firma/autorización y el piloto son pasos pendientes; no desactives controles para ejecutarlo.

Referencias: [política de asociaciones y mapeo GPO de Microsoft](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationdefaults), [configuración para profesionales de TI](https://techcommunity.microsoft.com/blog/askperf/how-to-configure-file-associations-for-it-pros/1313151), [registro de aplicaciones y capacidades](https://learn.microsoft.com/en-us/windows/win32/shell/default-programs). La compatibilidad de asociaciones no sustituye comprobar el [soporte de .NET en la edición de Windows instalada](https://learn.microsoft.com/en-us/dotnet/core/install/windows).
