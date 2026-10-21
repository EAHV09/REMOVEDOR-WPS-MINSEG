# Seguridad

La herramienta elimina software solamente después de una acción explícita en la interfaz. El análisis es de lectura. La elevación se pide con UAC y la interfaz se abre inicialmente como usuario normal.

## Protecciones implementadas

- Firma Authenticode, metadatos y SHA-256 para identificar ejecutables. Las comprobaciones de confianza usan la caché de Windows; si no se confirma la firma, el archivo queda para revisión.
- Argumentos separados mediante `ProcessStartInfo.ArgumentList`; ninguna cadena del registro se pasa a cmd.exe. GUID MSI validado y asistente sin reinicio automático ni Restart Manager para cerrar aplicaciones.
- Bloqueo temporal de rutas al comprobar un desinstalador elevado. Ancestros y EXE protegidos por ACL, sin enlaces ni directorios modificables por usuarios normales.
- Limpieza de archivo mediante el mismo handle usado para leer, verificar hash, respaldar y marcar para eliminar. Se rechazan enlaces, hardlinks y archivos cambiados. No se toma propiedad, no se cambian permisos de los programas y no se borran árboles recursivamente.
- Servicios: ejecutable confirmado, proceso propio y configuración completa sin cambios. Detención normal con espera limitada; nunca matar procesos por coincidencias de nombre.
- Tareas: una sola acción comprobada, XML sin cambios y tarea no ejecutándose. Run: cadena original sin cambios. Los huérfanos solo se admiten con inventario previo de esta sesión y configuración idéntica; los demás quedan para revisar.
- Evidencia de AnyDesk: se copian .trace/.conf/.log y connection_trace.txt en ubicaciones estándar y subcarpetas ad_. Grabaciones, documentos y datos de nube se conservan. Las ubicaciones personalizadas que no se puedan identificar requieren resguardo manual.
- Políticas: GUID propio, allow-all explícito para el resto de ejecutables y drivers, prohibición de reglas amplias de editor, auditoría antes de bloquear y promoción del XML exacto. No se modifica el antivirus ni otras políticas.
- AppLocker: reglas EXE/MSI con producto exacto y firma, servicios incluidos, Appx Allow explícito para proteger aplicaciones nativas. No se sustituye una política ajena ni se mezcla allow-all en ella. Equipos MDM requieren integración por TI. Servicio AppIDSvc iniciado en automático; su disponibilidad se mantiene después de desactivar.
- Transiciones AppLocker: bloqueo de escritor, snapshots inmutables por SHA-256 y manifiesto atómico, recuperación solo del estado anterior comprobado, confirmación de carga/desactivación mediante política local/efectiva, servicio y evento 8001 posterior a la petición. Un estado desconocido no se declara protegido.
- Registros y respaldos con ACL limitadas al usuario correspondiente o administradores/SYSTEM. El informe exportado contiene información del equipo, pero no las cadenas completas de comandos encontradas ni los archivos de evidencia.

## Límites

Un usuario con permisos de administrador puede modificar esta herramienta, sus registros o una política sin firma. El código abierto no equivale a protección contra manipulación ni a firma Authenticode. WPS/AnyDesk con certificados nuevos o identidad no reconocida se conservan para análisis. Los desinstaladores de los fabricantes siguen siendo programas externos: deben probarse con las versiones reales.

No se afirman «cero restos», «bloqueo universal» ni «aprobado por Bitdefender». El borrado automático de toda carpeta con un nombre parecido pondría en riesgo archivos ajenos. Los archivos protegidos o no identificados se muestran como pendientes cuando son descubiertos; no se puede garantizar la detección de cada variante.

No se han hecho cambios de software ni de políticas en la PC usada para desarrollar esta versión. No hay envío de datos a servicios externos. Cualquier envío de un informe o de una muestra al fabricante del antivirus debe hacerlo personal autorizado.

## Reportar un problema

No publiques informes con usuario, IP, MAC, rutas personales, contraseñas ni copias de configuración. Entrega a TI una descripción, versión, pasos, resultado esperado y mensajes sin datos sensibles. Conserva el informe completo y los respaldos en el repositorio interno autorizado de la institución.
