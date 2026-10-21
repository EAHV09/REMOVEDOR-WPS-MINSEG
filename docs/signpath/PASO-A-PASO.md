# Firma gratuita de la versión 3.1.1

## 1. Preparar GitHub

Repositorio exclusivo: https://github.com/EAHV09/REMOVEDOR-WPS-MINSEG

1. Activa la autenticación de dos factores de tu cuenta GitHub.
2. En **Actions**, ejecuta **Compilar candidato 3.1.1** en `main` y espera resultado correcto.
3. Revisa el EXE de `unsigned-candidate-3.1.1` y las evidencias. Todavía no tiene firma.
4. Publica una versión preliminar claramente marcada como **sin firma, solo pruebas**, enlazada al commit compilado. Las fuentes quedan públicas por separado.

## 2. Solicitar SignPath Foundation

Entra en https://signpath.org/apply.html. Usa la cuenta de contacto del mantenedor y los enlaces públicos del proyecto. No subas informes de equipos, respaldos ni credenciales. La descripción y política de firma están en README y CODE_SIGNING.md. No se necesita compartir contraseñas o tokens en un chat.

La Fundación revisa licencia, reputación verificable, mantenimiento, finalidad y origen de los binarios. La aceptación no está garantizada. Explica que el programa desinstala WPS por acción explícita, conserva documentos y no elude controles de Windows. Declara que los logos tienen derechos separados. Si exigen más historial, revisión o ajustes, resolverlos antes de activar firma.

## 3. Después de la aceptación

1. Activa MFA en SignPath.
2. Conecta la aplicación GitHub de SignPath **solo a este repositorio**. No selecciones todos los repositorios.
3. Vincula el proyecto SignPath a este origen y al sistema de compilación de confianza GitHub.com.
4. Asigna el mantenedor como aprobador, o las personas adicionales que requiera la Fundación. Usa aprobación manual y un token limitado a enviar solicitudes para este proyecto.
5. Configura dos definiciones de artefacto con los XML de esta carpeta: `artifact-helpers.xml` y `artifact-exe.xml`. El segundo exige el parámetro `version`.

## 4. Configurar GitHub sin exponer el token

En **Settings → Environments**, crea `signpath-release`. Limita despliegues a `main` y configura revisión de despliegue por el mantenedor cuando esté disponible. La aprobación manual en SignPath sigue siendo obligatoria.

En **Settings → Secrets and variables → Actions → Variables**, define:

| Variable | Valor |
|---|---|
| SIGNPATH_ENABLED | `false` hasta terminar la configuración; luego `true` |
| SIGNPATH_REPOSITORY | `EAHV09/REMOVEDOR-WPS-MINSEG` |
| SIGNPATH_ORGANIZATION_ID | ID que entrega SignPath |
| SIGNPATH_PROJECT_SLUG | Identificador real del proyecto |
| SIGNPATH_POLICY_SLUG | Política de firma de producción aprobada |
| SIGNPATH_HELPERS_CONFIG | Identificador real de la configuración de los dos PS1 |
| SIGNPATH_EXE_CONFIG | Identificador real de la configuración del EXE |
| SIGNPATH_CERTIFICATE_THUMBPRINT | Huella SHA-1 de 40 caracteres del certificado aprobado |

Guarda `SIGNPATH_API_TOKEN` como **secret del entorno signpath-release**, no como variable, archivo ni texto del repositorio. El token no debe tener permiso para aprobar su propia solicitud. Si el certificado cambia, confirma la nueva huella con SignPath antes de actualizarla.

Protege `main`: exige revisión para contribuciones externas, evita force-push y borrado, y revisa cualquier cambio de workflows o scripts antes de firmar. Si eres el único mantenedor, acuerda con SignPath una política que puedas cumplir; no inventes un segundo revisor.

## 5. Firmar

1. En **Actions → Firma SignPath 3.1.1 → Run workflow**, selecciona `main` y marca solicitar firma.
2. Revisa/aprueba el despliegue del entorno si GitHub lo solicita.
3. En SignPath, revisa y aprueba la primera solicitud: `AppLockerHost.ps1` y `BuildPolicy.ps1` propios del proyecto.
4. El flujo verifica ambas firmas y construye el EXE con esos bytes.
5. Revisa y aprueba la segunda solicitud: el EXE 3.1.1 generado por ese mismo flujo.
6. Descarga `signed-candidate-for-pilot` y `signed-build-evidence` solo si el flujo terminó correctamente. No publiques un artefacto de un flujo fallido.

Las solicitudes esperan hasta 30 minutos cada una. Si caducan, revisa su estado en SignPath antes de reintentar. Nunca descargues como final un artefacto sin comprobar su firma.

## 6. Verificar y probar

La evidencia debe indicar firma `Valid`, certificado autorizado, sello de tiempo y versión 3.1.1. El EXE firmado tendrá un SHA-256 distinto al candidato local sin firma. No cambies el contenido del EXE después de firmarlo; renombrar el archivo no cambia su contenido.

Prueba primero en una PC Windows 10 y otra Windows 11 con las protecciones activas. Respalda documentos, escanea, desinstala WPS, revisa pendientes y comprueba Office al siguiente inicio de sesión si corresponde. La firma no garantiza ausencia de bloqueos del dominio ni de detecciones del antivirus.

La guía [Office para TI](../OFFICE-AUTOMATICO-TI.md) detalla asociaciones y GPO. Esta preparación no instala certificados ni modifica la seguridad de las PC.

Referencias: [condiciones Foundation](https://signpath.org/terms.html), [integración GitHub](https://docs.signpath.io/trusted-build-systems/github), [firma admitida por Smart App Control](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control).
