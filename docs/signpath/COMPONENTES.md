# Componentes de la versión 3.1.0

| Componente | Licencia y tratamiento |
|---|---|
| Minseg.App y Minseg.Core | Código del proyecto, Apache-2.0 |
| AppLockerHost.ps1 y BuildPolicy.ps1 | Ayudantes del núcleo compartido, Apache-2.0; se firman antes de empaquetar |
| .NET / WindowsDesktop 10.0.12 x64 | Runtime Microsoft con avisos incluidos; no se re-firma como código propio |
| .NET SDK 10.0.401 | Solo compilación; fijado en global.json |
| Barlow y Source Sans 3 | SIL Open Font License 1.1 |
| Logos MINSEG, MINSEG.gob.pa, CIBERCOM e icono WPS derivado | Recursos suministrados para este proyecto, con derechos de marca separados; no se presentan como código Apache ni como aprobación institucional |
| Microsoft.NET.Test.Sdk, xUnit y transitivas | Solo pruebas; versiones y hashes en packages.lock.json y evidencia de cada compilación |
| APIs y herramientas Windows | No se redistribuye Windows |
| Desinstalador WPS | Software externo ya instalado; no se distribuye ni firma aquí |

El mantenedor ha solicitado la publicación de este proyecto con sus recursos. Los derechos de marca se conservan en NOTICE; la admisión de estos recursos queda sujeta a la revisión de SignPath Foundation. No se afirma una licencia general para reutilizar los logos.

El producto esperado es `REMOVEDOR DEL WPS MINSEG`, versión `3.1.0`. El ensamblado se llama `MINSEG-Control`. El núcleo compartido conserva componentes para otros productos, pero la interfaz y los argumentos aceptados de esta edición se limitan a WPS.

El proceso exige dependencias bloqueadas, origen nuget.org y consulta de vulnerabilidades disponible. Un fallo de consulta no se interpreta como ausencia de vulnerabilidades.
