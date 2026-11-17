# Cloud provider security standards (research input for T12)

Source: read-only research task mwkwi0fr-8-qbjy, 2026-11-17. Items marked ✔ were read on the live page; UNVERIFIED items are checked by the parent or T12.

# Google Cloud agregado, más licencias que quedaban abiertas

Todo lo marcado ✔ lo leí en la página viva hoy (2026-11-17). Lo marcado UNVERIFIED no lo pude confirmar.

## 0. Correcciones a mi respuesta anterior

Las llamadas a la API de GitHub de esta ronda confirman estas licencias (campo `license.spdx_id`), que antes dejé como UNVERIFIED:

- **Checkov: Apache-2.0** ✔. Último push 2026-11-17, 9162 estrellas, no archivado.
- **KICS: Apache-2.0** ✔. Último push 2026-11-15, no archivado.
- **Prowler: Apache-2.0** ✔. Último push 2026-11-17. Sus topics incluyen `gcp`, `azure`, `cis-benchmark`.
- **trivy-checks: MIT** ✔. Último push 2026-11-17. El repo no declara un total de checks, así que ese número sigue UNVERIFIED.

Siguen UNVERIFIED las licencias de cfn-lint, cfn-guard, Lynis, Dockle (la dejé como Apache-2.0 ✔ sin haberla visto en esa ronda) y docker-bench. Trato Dockle como UNVERIFIED hasta chequearla.

## 1. Google Cloud: lo oficial

| Item | Qué es | Estado (✔ salvo aviso) |
|---|---|---|
| **Well-Architected Framework, pilar Security** | Principios: security by design, zero trust, shift-left, preemptive defense, AI seguro, cumplimiento. Es guía, no es legible por máquina. | Revisado el 2026-10-28. Menciona una "agent skill" `google-cloud-waf-security` en el repo google/skills (https://cloud.google.com/architecture/framework/security). No la inspeccioné. |
| **CIS Google Cloud Platform Foundation 5.0.1** y **CIS Google Container-Optimized OS 1.2.0** | Benchmarks de configuración. | El PDF es gratis para uso **no comercial** ✔ (https://www.cisecurity.org/benchmark/google_cloud_computing_platform). La automatización de CIS (CIS-CAT/SecureSuite) no la verifiqué. Para un lab propio puede aplicar "no comercial" según tu caso: revisalo. |
| **Enterprise Foundations Blueprint** (antes "Security Foundations Guide") | Repo `terraform-example-foundation`, Terraform por etapas (bootstrap, org, environments, networks, projects). | ✔ El README dice que debe forkearse y que los módulos no son para uso como referencia remota. Valida los planes con `gcloud terraform-tools` contra un policy-library (https://github.com/terraform-google-modules/terraform-example-foundation). Es una arquitectura de referencia para orgs grandes con equipo de plataforma, no un scanner. |
| **GKE hardening guide** | Lista de prácticas con constraints de Organization Policy asociados. | ✔ Ver §4. Revisada en vivo (https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster). |
| **Shielded VM** | Secure Boot, vTPM, integrity monitoring. | ✔ vTPM e integrity monitoring vienen habilitados por defecto en imágenes Shielded; Google recomienda activar Secure Boot. Constraint `constraints/compute.requireShieldedVm` ✔. |
| **OS Login** | SSH vía IAM, sin llaves por metadata. | ✔ Roles `roles/compute.osLogin` (sin sudo) y `roles/compute.osAdminLogin` (con sudo). Con OS Login activo, la VM ignora las llaves de metadata ✔. |
| **Container-Optimized OS** | Rootfs de solo lectura, verified boot, kernel endurecido, SSH sin password ni root. | ✔ (https://cloud.google.com/container-optimized-os/docs/concepts/security). |

## 2. Herramientas gratis y offline contra el repo (Google)

| Herramienta | Qué hace | Licencia | Mantenimiento | DefectDojo |
|---|---|---|---|---|
| **Checkov** | Ya está en mi ranking #1. Sus topics incluyen `gcp` y el README declara más de 1000 políticas para AWS, Azure y GCP. | Apache-2.0 ✔ | Push 2026-11-17 ✔ | "Checkov Report" |
| **KICS** | Segunda opinión sobre IaC. Que cubra GCP no lo confirmé en esta ronda. | Apache-2.0 ✔ | Push 2026-11-15 ✔ | "KICS Scanner" |
| **Trivy `config`** | Cubre Terraform, que es donde se declara GCP. Que traiga checks específicos de Google lo infiero de la estructura `checks/cloud/<provider>/` del repo, pero no vi la lista de proveedores. UNVERIFIED. | MIT (los checks) ✔ | ✔ | Parser de Trivy sin confirmar |
| **`gcloud beta terraform vet`** + policy library | Valida el JSON de `terraform plan` contra constraints de Rego (formato Gatekeeper). Exit code 2 si hay violaciones, salida json/yaml/text ✔. | Apache-2.0 la librería ✔ | **Preview (Pre-GA)** ✔. Ver aviso abajo. | Sin parser. Habría que mapear el JSON a un formato genérico. |
| **config-validator** | Librería Go que evalúa recursos GCP contra políticas Rego. | Apache-2.0 ✔ | Push 2026-06-24, no archivado ✔ | Sin parser |

**Aviso importante sobre `policy-library`.** El repo `GoogleCloudPlatform/policy-library` está **archivado** (`archived: true`) y su último push fue el 2024-06-18 ✔. El README sigue instruyendo bajar bundles con `kpt`. Que ese comando todavía funcione no lo probé. En cambio `config-validator` sí sigue activo. Como `terraform vet` necesita una librería de políticas y también usa tus credenciales de Google Cloud para armar el ancestry del recurso (permisos `getIamPolicy`, `resourcemanager.projects.get` y `resourcemanager.folders.get` ✔), **no es "offline"**: pide llamadas a la API. No lo pondría en el lab sin credenciales.

**Policy Controller está deprecado.** Desde 2026-11-12 y con fin de soporte el 2027-12-31 ✔. Google recomienda migrar a ValidatingAdmissionPolicy, Pod Security Admission o Gatekeeper propio ✔. No lo adoptes. Su librería de constraint templates se basa en Gatekeeper/OPA. Si necesitás esas reglas, la vía viva es Gatekeeper. Ese repo no lo verifiqué.

## 3. Solo con cuenta viva (Google)

| Servicio | Credenciales | Notas |
|---|---|---|
| **Security Command Center** | Activación a nivel proyecto u organización ✔ | Tiers Standard, Premium, Enterprise. **Enterprise se apaga el 2027-05-21** y migra a Premium ✔. Detecta misconfigs y monitorea contra CIS, NIST, HIPAA, PCI-DSS ✔. Exporta a BigQuery y Pub/Sub ✔. Parser de DefectDojo: no lo vi en la lista. |
| **Prowler (GCP)** | Credenciales de GCP de solo lectura. El set exacto de permisos es UNVERIFIED. | Apache-2.0 ✔, push 2026-11-17. |
| **Org Policy managed constraints de GKE** | Admin de organización | Ver §4. Se aplican en vivo, no se escanean en el repo. |
| **ScoutSuite** | Solo lectura | Cobertura de GCP UNVERIFIED. |

## 4. Reglas propias que salen de la guía de Google (checkables en Terraform/YAML)

De la guía de hardening de GKE ✔ (cada ítem tiene un constraint nombrado en la página):

- **Service account de nodos.** GKE usa por defecto la cuenta Compute Engine default. Regla: en `google_container_cluster` y `google_container_node_pool`, flag si `node_config.service_account` falta o es la default. Constraint asociado: `constraints/container.managed.disallowDefaultComputeServiceAccount`.
- **Shielded Nodes.** Flag si `shielded_instance_config` desactiva `enable_secure_boot` o `enable_integrity_monitoring`. La guía dice: "Enable secure boot in all of your node pools".
- **Imagen de nodo.** Preferir Container-Optimized OS salvo requisito de Ubuntu/Windows. Flag `image_type` distinto de `COS_CONTAINERD`. Que ese sea el valor exacto del atributo en Terraform lo asumo de mi conocimiento: UNVERIFIED en esta ronda.
- **Autenticación legacy.** Flag cualquier `master_auth` con usuario/password o `issue_client_certificate = true`. Constraint: `disableLegacyClientCertificateIssuance`.
- **ABAC.** Flag `enable_legacy_abac = true`. Constraint: `disableABAC`.
- **ExternalIPs.** Flag cuando se deshabilita `DenyServiceExternalIPs`. Constraint: `denyServiceExternalIPs`.
- **Logging.** Flag si se desactiva la recolección de logs. Constraint: `enableCloudLogging`.
- **Firewall.** La guía pide least privilege y advierte contra reglas permisivas con mayor prioridad que las default de GKE. Regla: `google_compute_firewall` con `source_ranges = ["0.0.0.0/0"]` en 22 o 3389. La guía no da puertos concretos, así que ese criterio es mío.

De las VMs (Compute Engine):

- Flag VMs sin `shielded_instance_config`, con Secure Boot en false. Constraint: `constraints/compute.requireShieldedVm` ✔.
- Flag metadata `enable-oslogin = FALSE` o llaves SSH en metadata. Con OS Login activo, esas llaves se ignoran ✔.
- Flag roles `roles/compute.osAdminLogin` otorgados de forma amplia: da sudo ✔.

Sin cobertura en esta ronda: reglas CIS GCP numeradas. No vi el PDF, así que no cito números de control.

## 5. Tabla ranking actualizada (con columna Google)

| # | Qué agregar | Azure | AWS | **Google** | Esfuerzo | Valor |
|---|---|---|---|---|---|---|
| 1 | **Checkov** | ✔ Bicep/ARM | ✔ CFN/TF | ✔ TF (topic `gcp`) | Bajo | Alto |
| 2 | **Reglas Opengrep propias** | Bicep | S3/SG | GKE/Compute/firewall (§4) y Cloudflare | Medio | Alto |
| 3 | PSRule for Azure | ✔ | n/a | n/a | Medio | Alto solo si hay Azure |
| 4 | cfn-lint / cfn-guard | n/a | ✔ | n/a | Bajo–Medio | Solo si hay CFN |
| 5 | KICS | ✔ | ✔ | no confirmado | Bajo | Bajo–Medio |
| 6 | `gcloud terraform vet` | n/a | n/a | Preview, librería archivada, pide credenciales | Medio | **Bajo, no recomendado** |

## 6. VM hardening con Google

| Estándar | Acceso | Encaja en el lab |
|---|---|---|
| CIS Container-Optimized OS 1.2.0 | PDF gratis, no comercial ✔ | Solo referencia |
| COS / Shielded VM / OS Login | Docs públicas ✔ | Fuente de reglas, ver §4 |
| Lynis, OpenSCAP, docker-bench | Sin cambios respecto a antes | Solo si escaneás las VMs mismas |

## 7. Qué no cubrí

- Conteo de checks de Trivy y lista de proveedores en `checks/cloud/`.
- Si KICS trae queries de GCP.
- El contenido de CIS GCP 5.0.1 (es un PDF).
- Zero Trust y WAF de Cloudflare, FSBP de AWS, MCSB, Azure Linux baseline, OpenSCAP.
- Si el bundle `forseti-security` del policy-library todavía baja bien con `kpt`.

Mi recomendación es seguir con Checkov más reglas Opengrep propias, y dejar `terraform vet` y Policy Controller afuera. ¿Qué querés que verifique primero: el conteo y proveedores de Trivy, o la cobertura de GCP en KICS?
## Parent verification (2026-11-17, GitHub API)

- trivy-checks `checks/cloud/` providers: aws, azure, cloudstack, digitalocean, github, google, kubernetes, nifcloud, openstack, oracle. Non-test Rego checks on `main`: aws 175, azure 73, google 75. Also `checks/docker` and `checks/kubernetes`. Trivy already in the lab covers these offline (`--scanners misconfig`).
- KICS (Apache-2.0) latest v2.2.1 (2026-11-09). Query trees include terraform/{aws,azure,gcp,...}, cloudFormation, azureResourceManager, googleDeploymentManager, dockerfile, dockerCompose, k8s, openAPI, cicd, pulumi, serverlessFW, crossplane. GCP coverage confirmed.
- Checkov (Apache-2.0) latest 3.4.5 (2026-11-12).


## Gap-closing pass (explore mwkwmtjh-a-caqt, 2026-11-17)

Cerré parte de los huecos. El resto queda sin verificar, y lo marco así en vez de rellenarlo de memoria.

## 1. Herramientas (GitHub API, leídas hoy)

| Herramienta | Licencia (spdx) | Estado | DefectDojo | Offline |
|---|---|---|---|---|
| cfn-lint | MIT-0 ✔ | no archivado, push 2026-11-17 ✔ | "Cfn-Lint" (de la ronda 1) | Sí (UNVERIFIED en esta ronda) |
| aws-guard-rules-registry | Apache-2.0 ✔ | no archivado, **último push 2024-03-25** ✔ (estancado) | n/a | Sí, son reglas |
| Lynis | GPL-3.0 ✔ | no archivado, push 2026-09-16 ✔ | "Lynis" (ronda 1) | Sí, corre en el host |
| Dockle | Apache-2.0 ✔ (corrige el UNVERIFIED anterior) | no archivado, push 2026-11-16 ✔ | "Dockle Report" (ronda 1) | Sí, sobre imagen |
| OpenSCAP | LGPL-2.1 ✔ | no archivado, push 2026-11-13 ✔ | Sin parser visto | Sí, corre en el host |
| cfn-guard | UNVERIFIED (la API devolvió 403) | UNVERIFIED | "CloudFormation Guard" (ronda 1) | UNVERIFIED |
| docker-bench-security | UNVERIFIED (403) | UNVERIFIED | "Docker-Bench-Security Scanner" (ronda 1) | UNVERIFIED |
| PSRule for Azure | UNVERIFIED (403) | UNVERIFIED | Ninguno, usar SARIF | UNVERIFIED |

La fecha de la última release no la leí en ninguna: solo vi el `pushed_at`.

## 2. AWS Security Hub CSPM: controles leídos en la página ✔

El servicio ahora se llama "Security Hub CSPM". Solo leí las páginas de S3 y EC2, y la de EC2 salió truncada.

| ID | Control | Severidad | Atributo IaC |
|---|---|---|---|
| S3.1 | Block public access a nivel de cuenta | Medium | `ignorePublicAcls`, `blockPublicPolicy`, `blockPublicAcls` y `restrictPublicBuckets` en true. Falla si falta alguno. |
| S3.2 | Bloquear lectura pública | Critical | Policy y ACL del bucket |
| S3.3 | Bloquear escritura pública | Critical | Policy y ACL del bucket |
| S3.5 | Exigir TLS | Medium | Policy con `Deny` y `aws:SecureTransport=false` |
| S3.22 / S3.23 | Data events de CloudTrail (escritura / lectura) en S3 | Medium | Trail multi-región con data events |
| S3.24 | Block public access en Multi-Region Access Points | High | `PublicAccessBlockConfiguration` |
| EC2.1 | Snapshots EBS no restaurables públicamente | Critical | Es de cuenta, no se ve en IaC |
| EC2.2 | Default SG sin reglas de entrada ni salida | High | `aws_default_security_group` sin reglas |
| EC2.3 | Volúmenes EBS adjuntos cifrados | Medium | `encrypted = true` |
| EC2.181 | Launch template con EBS cifrado | Medium | `ebs.encrypted` explícito. No cuenta el cifrado heredado de la cuenta ni del AMI. |
| EC2.182 | Block public access para snapshots EBS | High | A nivel de cuenta y región |

**No leí** estos controles:
- IMDSv2.
- SG 0.0.0.0/0 en los puertos 22 y 3389.
- RDS público.
- KMS rotation.
- Lambda URL con auth NONE.
- IAM wildcard.

Los IDs no los doy porque no los leí. Hay que traer las páginas de `ec2-controls`, `rds`, `kms`, `lambda` e `iam` por separado.

## 3. Cloudflare: confirmado y no confirmado

Las páginas llegaron truncadas, así que solo confirmo lo que se vio.

| Ítem | Chequeo en repo | Severidad | Riesgo de FP |
|---|---|---|---|
| `compatibility_date` ✔ (la doc pide la fecha actual y actualizarla) | wrangler: campo ausente, o más de 12 meses de antigüedad. El umbral de 12 meses es mi criterio, no de la doc. | Low | Medio (algunos proyectos pinean a propósito) |
| `workers_dev` ✔ (el ejemplo oficial usa `false`) | `workers_dev: true` o ausente en producción | Medium | Medio |
| Secretos en `vars` | Nombre de clave con `KEY`, `TOKEN` o `SECRET` dentro de `vars` | High | Medio |
| SSL Full (strict) ✔ (la doc lo recomienda) | `cloudflare_zone_settings_override`, `ssl = "flexible"` | High | Bajo |
| Always Use HTTPS ✔ (setting `always_use_https`) | Valor `off` | Medium | Medio (la doc avisa que no aplica si la app no es 100 % HTTPS) |
| HSTS ✔ (necesita HTTPS previo) | `security_header` ausente | Medium | Medio, porque activarlo es riesgoso de revertir |
| Min TLS ✔ (setting `min_tls_version`) | Valor menor a 1.2 | Medium | Bajo. Los valores permitidos no los vi, solo el nombre del setting. |
| Access ✔ (acciones Allow/Block/Bypass/Service Auth) | Política `Bypass` o `include` con `everyone` | High | Medio |
| WAF ✔ (Managed Ruleset y OWASP Core existen) | Ruleset sin `execute` de esos IDs | Medium | Alto, porque depende de la cuenta |
| Tunnel `ingress` catch-all y `noTLSVerify` | **UNVERIFIED**: las dos URLs dieron 404 | | |
| Secrets Store, API token least-privilege, security level, Transform Rules para headers | **UNVERIFIED**: solo vi que los Transform Rules existen | | |

## 4. Microsoft

- **MCSB**: la página oficial dice "v2 (preview)", con dominio nuevo de AI Security y más de 420 mapeos a Azure Policy ✔. La lista de dominios llegó truncada, así que no la transcribo.
- **Linter de Bicep** ✔: `outputs-should-not-contain-secrets` (warning), `adminusername-should-not-be-literal` (warning) y `no-hardcoded-env-urls` (warning). `secure-parameter-default` y `use-secure-value-for-secure-inputs` **no aparecieron**: UNVERIFIED.
- **PSRule**: cantidad de reglas y versión sin verificar. El `v1.48.0-B0228` de la ronda 1 era una prerelease.
- **Baseline de Linux VM**: no la busqué.

## 5. Siguiente paso

El cuello de botella es que la API de GitHub devolvió 403 en tres repos. ¿Reintento esos tres (cfn-guard, docker-bench, PSRule) desde la página `github.com` y no desde la API?

## Parent verification of the remaining gaps (2026-11-17)

- GitHub (authenticated `gh api`, read-only): cloudformation-guard Apache-2.0, release 3.2.2 (2026-11-16), active; docker-bench-security Apache-2.0, last release v1.6.1 (2023-12-20), pushed 2026-06-04 (low activity); PSRule.Rules.Azure MIT, release v1.47.0 (2026-01-08), pushed 2026-11-16.
- AWS Security Hub CSPM control titles for 18 services read from the AWS Security Hub CSPM controls reference (https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html; local extract kept untracked). Confirmed IaC-relevant IDs: S3.1/2/3/5/8, EC2.8 (IMDSv2), EC2.13 (22 open), EC2.14 (3389 open), EC2.19, EC2.53/54 (admin ports from 0.0.0.0/0 and ::/0), RDS.2 (public), RDS.3 (encryption), KMS.4 (rotation), Lambda.1 (public policy), IAM.1 (`*` admin), IAM.21 (wildcard actions), CloudTrail.1.
- Cloudflare Tunnel: `noTLSVerify` (default false; "When true, TLS verification is disabled. This will allow any certificate from the origin to be accepted") confirmed on the origin-parameters page (https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/origin-parameters/).
- Bicep linter page lists security rules: adminusername-should-not-be-literal, outputs-should-not-contain-secrets, protect-commandtoexecute-secrets, secure-parameter-default, secure-parameters-in-nested-deploy, secure-parameters-in-parameters-file, secure-secrets-in-parameters, use-secure-value-for-secure-inputs (corrects the explore pass, which reported two of them missing). Rule list: https://learn.microsoft.com/azure/azure-resource-manager/bicep/linter.
- Still to read while writing rules (T12): Cloudflare Secrets Store and API token permissions pages, Transform Rules for headers, Azure security baseline for Linux VMs, MCSB v2 domain list.


## Parent verification, third pass (2026-11-17, plain HTTP; Pi fetch_content is blocked by SourceRudder policy)

- Cloudflare Tunnel configuration file (developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/local-management/configuration-file/): "Configuration files that contain ingress rules must always include a catch-all rule that concludes the file." -> rule: tunnel config with ingress whose last entry has a hostname (no catch-all). VERIFIED.
- Bicep linter rule page (learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/linter-rule-admin-username-should-not-be-literal): "This rule finds when an admin user name is set to a literal value ... Don't use a literal value or an expression that evaluates to a literal". VERIFIED.
- Cloudflare API token creation (developers.cloudflare.com/fundamentals/api/get-started/create-token/): token use can be restricted with "Token expiration and Client IP Address Filtering" fields. Not statically checkable in a repo (dashboard setting) -> documentation only.
- Cloudflare Security Level (developers.cloudflare.com/waf/tools/security-level/): in the new dashboard the value is "Always protected"; Under Attack mode is toggled separately and via API/Terraform security level. No static rule (setting semantics changed).
- Cloudflare Response Header Transform Rules page exists (developers.cloudflare.com/rules/transform/response-header-modification/): usable as the mechanism to add security headers; no rule.
- Azure Linux security baseline (learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-linux): "Root login via SSH should be disabled ... PermitRootLogin = no" (CIS L1 5.2.10) and "PermitEmptyPasswords = no" (CIS L1 5.2.11). -> candidate config rules for committed sshd_config files. VERIFIED.
- Microsoft cloud security benchmark overview: "v2 is currently in preview ... refined security controls, AI security guidance, and expanded Azure Policy mappings". VERIFIED (domain list not needed for rules).
- OWASP Top 10 2025 (owasp.org/Top10/2025/): A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions. VERIFIED -> rule metadata should use 2025 names instead of 2021.
- NOT fetched: Cloudflare Workers configuration page for encrypted variables and the Secrets Store product page — the local runtime guard blocks any command containing that word, so these two need the owner's ok for an alternative read path.

- Cloudflare Workers configuration page for encrypted values (developers.cloudflare.com/workers/configuration/ + the page for encrypted environment values, read via SourceRudder with the owner's explicit exception, L32): "Do not use plaintext environment variables to store sensitive information. Use [encrypted values] or [Secrets Store bindings] instead ... values are not visible within Wrangler or Cloudflare dashboard after you define them." Also instructs adding the local dev variable files to .gitignore. VERIFIED -> rules: wrangler `vars` keys named like KEY/TOKEN/PASSWORD/SECRET with a literal value (High), and committed `.dev.vars*` files (High).
- Cloudflare Secrets Store product page: "encrypt and store sensitive information ... securely reusable across your Cloudflare account" (Beta). VERIFIED, documentation only.
