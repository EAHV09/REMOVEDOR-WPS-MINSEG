# Colaborar

El mantenedor y las responsabilidades de firma están en CODE_SIGNING.md. La licencia del código no concede derechos de marca sobre los logos.

Los cambios se proponen en una rama y pasan por revisión. Explica qué cambia, cómo se comprueba y si toca desinstalación, limpieza, permisos o políticas de Windows. Usa casos de prueba con datos inventados. No adjuntes respaldos de usuarios, credenciales, instaladores ajenos, certificados privados ni informes completos de equipos.

Para preparar un candidato, usa `scripts/Build-SignPathCandidate.ps1` con una carpeta nueva. El SDK exacto está en `global.json`; los archivos `packages.lock.json` deben ir en el repositorio. Al actualizar una dependencia, SDK o runtime, regenera los locks de forma explícita, revisa las diferencias y repite las pruebas. Nunca cambies automáticamente el lock durante una firma.

Las operaciones reales de desinstalación se prueban en una PC piloto o VM con respaldo y acceso alternativo, siguiendo `docs/GUIA.md`. Las pruebas de compilación no aplican políticas a la PC del desarrollador.

Los cambios en `.github/workflows`, `scripts`, `NuGet.Config`, archivos de proyecto y `docs/signpath` requieren revisión de quien administra las firmas. CODEOWNERS identifica al mantenedor. Configura las protecciones de rama y entorno antes de activar firma.

Cada candidato firmado necesita aprobación manual y un piloto documentado. La aceptación de un pull request no autoriza por sí sola publicar una versión.
