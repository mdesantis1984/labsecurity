# Documentación de LabSecurity

[Inicio en español](../README.md) · [English documentation](README.en.md)

Esta página organiza la documentación por necesidad y hace visible el estado de traducción. El español es la entrada principal del repositorio; la referencia técnica permanece en inglés mientras avanzan las siguientes unidades del programa documental.

## Elegir un recorrido

| Necesidad | Comenzar por | Idioma actual |
| --- | --- | --- |
| Conocer el laboratorio e instalarlo | [README principal](../README.md) | Español e inglés |
| Instalar y usar la skill desde un agente | [Prompts del README](../README.md#probarlo-en-minutos) y [integración con agentes](AGENT-INTEGRATION.md) | Español e inglés; la integración, en inglés |
| Ejecutar comandos y leer el JSON | [Referencia de la CLI](CLI.md) | Inglés, traducción pendiente |
| Aplicar la compuerta previa a un PR | [Compuerta](GATE.md) | Inglés, traducción pendiente |
| Clasificar hallazgos y generar tareas | [Triaje](TRIAGE.md) | Inglés, traducción pendiente |
| Conocer reglas, fuentes y licencias | [Reglas](RULES.md) y [avisos de terceros](../THIRD_PARTY_NOTICES.md) | Inglés, traducción pendiente |
| Elegir sistema operativo y carpeta de datos | [Plataformas](PLATFORMS.md) | Inglés, traducción pendiente |
| Respaldar y restaurar las bases de datos | [Copias de seguridad](BACKUP.md) | Inglés, traducción pendiente |
| Revisar versiones e imágenes fijadas | [Versiones](VERSIONS.md) | Inglés, traducción pendiente |
| Entender el análisis de taint de SonarQube | [SonarQube y taint](SONAR-TAINT.md) | Inglés, traducción pendiente |
| Comprender decisiones y fronteras | [Arquitectura](architecture.md) | Inglés, traducción pendiente |
| Contribuir y revisar cambios | [Contribución](../CONTRIBUTING.md) y [gobierno](governance.md) | Inglés, traducción pendiente |
| Reportar una vulnerabilidad | [Política de seguridad](../SECURITY.md) | Inglés, traducción pendiente |
| Consultar la investigación de estándares | [Notas de investigación](research/standards-catalog.md) | Inglés y español |

## Contrato documental

- Las capacidades se documentan sólo cuando tienen evidencia ejecutable: una prueba o una verificación real.
- El estado de cada plataforma distingue lo probado de lo diseñado; macOS y WSL2 no se presentan como probados.
- Los comandos deben poder copiarse y ejecutarse desde la ruta indicada.
- Las versiones viven en `compose.yaml`, los Dockerfiles y [Versiones](VERSIONS.md); la prosa no inventa estados.
- Los documentos español/inglés deben conservar la misma estructura y las mismas afirmaciones verificables.

## Estado del programa

| Unidad de trabajo | Estado |
| --- | --- |
| Entrada de producto con español como idioma principal y espejo inglés | Disponible |
| Referencia de CLI, compuerta, triaje, reglas, plataformas y copias de seguridad | Disponible, en inglés |
| Arquitectura y gobierno del repositorio | Disponible, en inglés |
| Validación automática de enlaces relativos en CI | Disponible |
| Traducción al español de la referencia técnica | Pendiente |
| Ejecución verificada en macOS y WSL2 | Pendiente |
