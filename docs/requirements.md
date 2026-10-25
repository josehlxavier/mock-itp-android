# Catálogo de requisitos M01–M03

`L` significa validado em laboratório. `P` significa pendente no sandbox. Os nomes citados correspondem a testes executáveis em `apps/backend/test`; resultados consolidados da entrega estão em `validation.md`. RFCs e snapshots fixados estão em `contracts.md`.

| ID | Requisito e referência | Implementador | Evidência / resultado |
|---|---|---|---|
| M01.01 | Laboratório/sandbox separados (plano §6) | config/runtime/lab | Segurança: sandbox rejeita loopback; L |
| M01.02 | Organização/software, callbacks e origens (Diretório/DCR-BR 2.1.0) | config, directory.ssa | SSA válido e origem não autorizada; L |
| M01.03 | Importação, chave correspondente, validade e cadeia (Certificados 3.0) | security/certificates | Certificado expirado, incompatível e cadeia inválida; L; cadeia ICP real P |
| M01.04 | Organizações/marcas/ASs e APIs publicadas (Participantes 1.1.0) | directory/service | Funcional: duas organizações e recursos descobertos; L |
| M01.05 | OIDC/issuer e aliases mTLS (OIDC Discovery, RFC8705 §5) | directory/service | Funcional: aliases; segurança: issuer divergente; L |
| M01.06 | Instituição–AS–recursos–cliente registrado (plano M01) | directory/dcr, chave persistente | Clientes diferentes por AS; reinício mantém cliente; L |
| M01.07 | JWKS pública associada ao SSA (DCR-BR 2.1.0) | app, directory, dcr.desired | JWKS sem material privado; validação da chave publicada; L |
| M01.08 | Cache controlado e atualização (escolha interna) | directory/service | Funcional: cache evita chamadas e refresh as repete; L |
| M02.01 | TLS/mTLS, cadeia/hostname e revogação (RFC8705, Certificados 3.0) | transport/certificates | Handshakes sem certificado, expirados/revogados, hostname e CA inválidos; L |
| M02.02 | Transporte BRCAC e assinatura BRSeal separados | certificates/CryptoService | Rotação e rejeição de uso incompatível; L |
| M02.03 | private_key_jwt (RFC7523) | CryptoService/dcr.tokenProbe | Token obtido no laboratório e assertion reutilizada rejeitada; L |
| M02.04 | PS256, kid/use/alg e rejeição de chave ambígua (RFC7515) | security/jose | Algoritmo, kid, chave duplicada e adulteração; L |
| M02.05 | JWE RSA-OAEP/A256GCM (RFC7516, plano M02) | security/jose | Round-trip aninhado e ciphertext adulterado; L |
| M02.06 | Claims e replay por categoria (RFC7523/RFC9101/FAPI-BR2.2.1 §6.1) | security/jose, itp_replay | iss/aud/sub/iat/exp/jti/state/nonce/PKCE; recursos com UUID v4 e replay 24 h; L |
| M02.07 | Assinatura de recurso application/jwt e chaves do Diretório | CryptoService, directory.verifyResource | Mensagem com issuer de organização, audiência de recurso e replay; L; operações M05/M06 P |
| M02.08 | Headers FAPI/correlação/idempotência (OAS aplicável) | transport.fapiHeaders | Rejeita correlação, IP e idempotency key inválidos; L; headers por operação futura P |
| M02.09 | Logs/erros sanitizados (plano §10) | app/errorHandler/transport.audit | Respostas e armazenamento sem segredos em claro; auditoria mínima; L |
| M03.01 | Obter e validar SSA (DCR-BR 2.1.0, Diretório) | directory.ssa | SSA assinado recente aceito; issuer/idade/origens inválidos rejeitados; L |
| M03.02 | Registro JSON por mTLS, metadados confidenciais (DCR-BR2.1/OAS2.0.1/RFC7591) | dcr.service | Registro válido/inválido/repetido, contrato de resposta; L; sandbox P |
| M03.03 | Persistir client_id, URI/token e metadados (RFC7592) | Vault/PostgresStore | Banco real e runtimes independentes; L |
| M03.04 | GET/PUT/DELETE, token estável DCR-BR2.1 e tratamento de provedor divergente RFC7592 | dcr.manage | DCM padrão, teste explícito de rotação divergente e exclusão; L |
| M03.05 | Rotação de certificados e Software Statement (plano M03) | fingerprint, dcr.register | Muda assinatura/transporte/origem sem duplicar cliente; L |
| M03.06 | Evitar registros duplicados e tratar timeout (plano M03) | locks, pending/uncertain | Concorrência, timeout após criação e resposta inválida bloqueiam novo POST; L |
| M03.07 | Reconciliação explícita (escolha operacional interna) | dcr.reconcile, CLI | Confirma registro remoto antes de reativar; L |
| M03.08 | Token válido, audiência/escopo/certificado (RFC8705) | lab.token e /lab/protected | Recurso aceita token correto e rejeita outro certificado; L |
| G01 | Dependências e contratos fixados (plano §10) | package-lock, sources.json, Dockerfile | Checksums dos snapshots e imagens por digest; L |
| G02 | Laboratório não prova sandbox (plano §6/§10) | modo explícito, documentação | Health retorna simulated; sem fallback; L |
| G03 | DCR/DCM e autenticação contra AS real nas versões-alvo | integração externa | P: faltam credenciais e testes de interoperabilidade |

Não estão neste incremento: aplicativo Android/Compose, Credential Manager, Digital Asset Links, console web completo, sessões OAuth/callback, Enrollments/Pagamentos ou jornadas M04+. As primitives de request object não implementam a máquina de estados OAuth. Não há resultado de homologação FAPI/Open Finance, consulta OCSP online/atualização automática de CRL, HSM/KMS ou teste contra sandbox real.
