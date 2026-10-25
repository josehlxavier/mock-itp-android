# Plano técnico — Wallet Experimental e Backend ITP

**Projeto:** Open Finance Wallet Simulator  
**Ambiente-alvo:** Sandbox Open Finance Brasil  
**Aplicações:** Android nativo + Backend ITP + Console técnico  
**Especificações-alvo:** Enrollments v2.3.0, Pagamentos v5.0.0, FAPI-BR v2.2.1, DCR-BR v2.1.0 e Padrão de Certificados v3.0.

## 1. Objetivo

Desenvolver uma aplicação Android que simule uma wallet vinculada a uma ITP, acompanhada de um backend que implemente efetivamente o papel de cliente confidencial das APIs do Open Finance Brasil.

A plataforma deverá permitir o registro dinâmico da ITP junto aos Authorization Servers das instituições detentoras, o estabelecimento de vínculos de dispositivos com FIDO2, a criação e autorização de consentimentos Pix e a iniciação de pagamentos no sandbox.

O projeto servirá de base para experimentações futuras de autorização offline de pagamentos Pix, preservando a integração com a Jornada Sem Redirecionamento.

## 2. Diretrizes arquiteturais

A solução terá três componentes:

**Aplicativo Android:** Kotlin, Jetpack Compose e Credential Manager. Responsável pela experiência do pagador, criação e utilização das passkeys e comunicação com o backend.

**Backend ITP:** Node.js 24+, TypeScript e framework HTTP estruturado (preferencialmente Fastify ou NestJS). Responsável por DCR/DCM, OAuth2/OIDC, FAPI-BR, mTLS, JOSE, APIs Enrollments e Pagamentos, persistência e orquestração.

**Console técnico:** interface administrativa para configurar ambientes, observar DCR/DCM, inspecionar fluxos, acompanhar estados e executar testes. Não deverá expor chaves privadas, tokens integrais ou dados sensíveis desnecessários.

Utilizar PostgreSQL para persistência, armazenamento seguro de segredos e Docker Compose para a execução do ambiente de desenvolvimento.

O backend deverá suportar múltiplas detentoras e seus respectivos Authorization Servers, não apenas o Mock Bank.

## 3. Módulos do backend

### M01 — Configuração de ambiente e Diretório

Implementar:

- Configuração separada para laboratório local e sandbox.
- Cadastro dos metadados da organização/ITP e do Software Statement.
- Importação e validação dos certificados e suas cadeias.
- Integração com o Diretório de Participantes.
- Identificação das organizações e marcas disponíveis no sandbox.
- Descoberta das APIs de Enrollments e Pagamentos publicadas pelas detentoras.
- Associação entre instituição, Authorization Server, endpoints de recursos e cliente OAuth registrado.
- Descoberta dos metadados OIDC do AS, respeitando `mtls_endpoint_aliases` quando aplicável.
- Publicação da JWKS da ITP e associação ao Software Statement.
- Atualização e cache controlado de metadados.

**Aceite:** selecionar uma detentora e descobrir corretamente seus endpoints de autorização, token, PAR, DCR/DCM e recursos, sem depender de URLs fixas no código.

### M02 — Segurança FAPI-BR e criptografia

Implementar uma camada reutilizável para:

- mTLS, validação de certificado servidor, cadeia de confiança e hostname.
- Certificado de aplicação cliente (BRCAC) para transporte.
- Certificado de assinatura (BRSeal) para JWS.
- Autenticação `private_key_jwt`.
- Construção e validação de JWT/JWS/JWE conforme o contexto.
- JOSE Header apropriado a cada artefato criptográfico.
- Algoritmos de assinatura `PS256` e criptografia `RSA-OAEP` + `A256GCM`, quando exigidos.
- Validação de assinaturas e chaves publicadas no Diretório.
- Controle de `iss`, `aud`, `sub`, `iat`, `exp`, `jti`, `nonce` e `state`, conforme o tipo de token ou mensagem.
- Rejeição de algoritmos não permitidos, tokens inválidos e assinaturas inconsistentes.
- Assinatura e validação de payloads `application/jwt` nas operações que os exigirem.
- Tratamento dos headers FAPI, correlação e idempotência previstos em cada OAS.
- Registro sanitizado de erros de assinatura, TLS e autorização.

Separar explicitamente as regras para três categorias: client assertions OAuth, request objects OAuth/OIDC e mensagens assinadas das APIs de recursos. Não reutilizar indiscriminadamente os mesmos claims ou headers JOSE entre essas categorias.

**Aceite:** executar testes positivos e negativos de assinatura, mTLS, audiência, emissor, expiração, replay e seleção de chaves.

### M03 — Dynamic Client Registration e Management

Implementar o ciclo de vida completo por Authorization Server:

1. Obter o SSA da ITP.
2. Consultar os metadados do AS.
3. Montar a solicitação DCR conforme a versão vigente.
4. Utilizar mTLS no registro.
5. Declarar os parâmetros de autenticação, redirect URIs, JWKS URI, algoritmos e funcionalidades necessárias.
6. Enviar o registro e validar a resposta.
7. Persistir com segurança o `client_id`, o `registration_client_uri`, o `registration_access_token` e demais metadados retornados.
8. Permitir consultas, atualizações e exclusão via DCM, conforme RFC 7592 e DCR-BR.
9. Tratar rotações de certificados e alterações do Software Statement.
10. Impedir registros duplicados desnecessários, priorizando a manutenção do cliente existente.

Incluir os valores de `software_origin_uris` apropriados para a aplicação Android. Mudanças que afetem essas origens deverão ser refletidas no Diretório/SSA e propagadas por DCM quando necessário.

**Aceite:** registrar a aplicação em um AS do sandbox, recuperar os dados do cliente, atualizar seu registro e utilizá-lo para obter tokens válidos.

### M04 — OAuth2, OIDC e autorização

Implementar:

- Fluxo `client_credentials`.
- Fluxo de autorização interativa exigido para o estabelecimento do vínculo.
- Geração de request objects assinados.
- Suporte a PAR.
- Tratamento de `response_type`, `state`, `nonce`, PKCE e demais parâmetros conforme o perfil aplicável.
- Troca de authorization code por tokens.
- Validação de ID Token e descriptografia quando exigida.
- Tokens associados aos escopos e recursos de consentimento/vínculo.
- Tratamento de emissão, expiração, renovação e invalidação de tokens.
- Aplicação dos `scope` exigidos por cada operação.
- Suporte ao mecanismo de obtenção de tokens previsto para a JSR, sem assumir que seja idêntico à autorização tradicional.
- Detecção de comportamentos incompatíveis do Authorization Server.

Implementar uma máquina de estados explícita para as sessões OAuth, com proteção contra callback duplicado, replay e troca indevida de sessão.

**Aceite:** executar a jornada OAuth necessária para criar um vínculo de dispositivo, obter os tokens apropriados e acessar os endpoints protegidos.

### M05 — Cliente da API Enrollments v2.3.0

Implementar os seguintes métodos da API:

| Método | Operação |
|---|---|
| POST `/enrollments` | Criar vínculo |
| GET `/enrollments/{enrollmentId}` | Consultar vínculo |
| PATCH `/enrollments/{enrollmentId}` | Revogar/rejeitar vínculo |
| POST `/enrollments/{enrollmentId}/risk-signals` | Enviar sinais de risco |
| POST `/enrollments/{enrollmentId}/fido-registration-options` | Obter opções de registro |
| POST `/enrollments/{enrollmentId}/fido-registration` | Registrar credencial FIDO2 |
| POST `/enrollments/{enrollmentId}/fido-sign-options` | Obter challenge de autenticação |
| POST `/consents/{consentId}/authorise` | Autorizar consentimento Pix |

Implementar os contratos conforme os schemas oficiais, incluindo headers, autenticação, assinatura, escopos e validações.

O backend deverá persistir o identificador do vínculo, sua instituição detentora, estados, datas relevantes, limites e identificadores públicos das credenciais associadas.

Deverá existir suporte explícito às transições de estado do vínculo e tratamento de timeouts.

**Aceite:** completar o registro FIDO2 de um vínculo, consultá-lo em status `AUTHORISED`, obter um challenge posterior e autorizar um consentimento Pix utilizando a credencial registrada.

### M06 — Cliente da API Pagamentos v5.0.0

Implementar a integração da família de Pagamentos, incluindo os métodos de criação, consulta e operações de manutenção suportadas pela OAS.

Priorizar:

| Método | Operação |
|---|---|
| POST `/consents` | Criar consentimento Pix |
| GET `/consents/{consentId}` | Consultar consentimento |
| POST `/pix/payments` | Iniciar Pix |
| GET `/pix/payments/{paymentId}` | Consultar pagamento |
| GET `/consents/{consentId}/pix/payments` | Consultar pagamentos associados |
| PATCH `/pix/payments/{paymentId}` | Cancelar pagamento quando aplicável |
| PATCH `/consents/{consentId}/pix/payments` | Cancelamento abrangente quando aplicável |

A cobertura integral da OAS deverá ser catalogada, mas o fluxo funcional prioritário será **Pix imediato, individual, via JSR**, sem agendamento ou recorrência.

Implementar `authorisationFlow = FIDO_FLOW` quando exigido pelo contrato e suportado pelo fluxo.

O backend deverá gerenciar criação, autorização, iniciação, consulta e reconciliação do status do pagamento.

**Aceite:** criar um consentimento, autorizá-lo pela JSR, iniciar um Pix simulado e acompanhar seu resultado terminal no sandbox.

### M07 — Orquestrador de jornadas

Criar uma camada que coordene os módulos OAuth, Enrollments e Pagamentos, sem embutir regras de protocolo nas telas Android.

Implementar duas jornadas principais:

**Jornada de vinculação:**

- Usuário escolhe detentora.
- Backend inicia criação do vínculo.
- Wallet fornece sinais de risco.
- Usuário realiza a autorização interativa exigida pela detentora.
- Backend obtém parâmetros FIDO2.
- Android executa criação de credencial.
- Backend encaminha a resposta FIDO2.
- Vínculo alcança o estado autorizado.

**Jornada de pagamento:**

- Wallet informa dados de um Pix imediato.
- Backend cria consentimento.
- Backend solicita challenge FIDO2 vinculado ao consentimento.
- Wallet executa assertion.
- Backend encaminha resposta à detentora.
- Consentimento é autorizado.
- Backend solicita iniciação do Pix.
- Backend consulta resultado até o estado terminal ou até um limite operacional definido.

Cada jornada deve preservar seus identificadores, estados, eventos e erros, permitindo retentativas controladas quando permitidas e evitando duplicidade de operações.

### M08 — Banco de dados e auditoria

Persistir, no mínimo:

- Configuração de ambientes e organizações.
- Software Statements e referências dos certificados.
- Metadados de detentoras e Authorization Servers.
- Clientes DCR registrados.
- Referências seguras de credenciais e tokens.
- Usuários simulados e wallets.
- Vínculos e credenciais FIDO2.
- Consentimentos e pagamentos.
- Sessões OAuth e jornadas.
- Registros de execução, erros, latência e correlação.
- Chaves de idempotência e histórico de tentativas.

Não persistir chaves privadas FIDO2 da wallet. Segredos de infraestrutura deverão ficar em armazenamento protegido, com referências no banco sempre que possível.

## 4. Aplicativo Android

Criar uma aplicação nativa com as seguintes telas:

| Tela | Funcionalidade |
|---|---|
| Inicial | Exibir ambiente, conexão com backend e wallet ativa |
| Instituições | Selecionar detentora disponível |
| Vínculos | Listar vínculos, estados, limites e instituição |
| Nova vinculação | Executar a jornada de enrollment |
| Passkeys | Registrar e utilizar credenciais via Credential Manager |
| Novo Pix | Informar valor e destinatário de teste |
| Autorizar Pix | Exibir dados do consentimento e executar assertion |
| Histórico | Consultar consentimentos e pagamentos realizados |
| Diagnóstico | Exibir etapa atual, identificadores e erros sanitizados |

Requisitos adicionais:

- Utilizar Android Credential Manager, sem criar uma implementação criptográfica própria de FIDO2.
- Suportar Digital Asset Links e origens Android autorizadas.
- Receber os parâmetros FIDO2 produzidos pela detentora.
- Encaminhar os retornos WebAuthn sem alterar indevidamente os dados assinados.
- Permitir múltiplos vínculos e credenciais.
- Não acessar diretamente os endpoints protegidos da detentora.
- Identificar visualmente o ambiente de sandbox.
- Preservar o aplicativo da PoC 1A como referência de comportamento offline.

A aplicação deverá inicialmente operar online, para validar a JSR de ponta a ponta.

## 5. Console de administração

Disponibilizar uma interface web local ou restrita, com:

- Gerenciamento dos ambientes.
- Importação e estado dos certificados.
- Consulta ao Diretório e seleção de detentoras.
- Execução e acompanhamento de DCR/DCM.
- Configuração de JWKS, origens e callbacks.
- Visualização de sessões OAuth e seus estados.
- Histórico de chamadas Open Finance, incluindo método, endpoint, status HTTP, latência e `x-fapi-interaction-id`.
- Linha do tempo das jornadas de vínculo e pagamento.
- Inspeção sanitizada dos headers JOSE e claims de mensagens.
- Filtros de erros por camada: transporte, certificado, autenticação, consentimento, FIDO2 e pagamento.

O console deverá deixar clara a diferença entre dados recebidos efetivamente das APIs e dados simulados.

## 6. Modos de execução

Implementar dois modos de backend:

**Laboratório local:** utiliza um simulador controlado de Authorization Server e recursos, para permitir desenvolvimento, testes negativos e reprodução de erros, sem dependência do sandbox externo.

**Sandbox Open Finance:** utiliza DCR/DCM real, metadados do Diretório, Authorization Servers e APIs de recursos efetivamente disponibilizados pelas detentoras ou pelo Mock Bank.

Não utilizar respostas simuladas silenciosamente no modo sandbox.

## 7. Testes obrigatórios

Implementar testes de unidade, contrato, integração e fluxo completo.

Cobrir principalmente:

- DCR válido, inválido e repetido.
- DCM com alteração de metadados e rotação de credenciais.
- Falha de mTLS e certificados expirados/incompatíveis.
- JWT com algoritmo ou `kid` incorreto.
- `client_assertion` inválida, expirada ou reutilizada.
- JWS com assinatura ou claims inválidos.
- Token com escopo, audiência ou vinculação incorretos.
- Callback OAuth com `state` ou `nonce` divergente.
- Falha de registro ou autenticação FIDO2.
- `origin` não permitida pelo SSA.
- Tentativa de autorização com challenge reutilizado.
- Consentimento rejeitado, expirado ou revogado.
- Pagamento rejeitado, pendente ou concluído.
- Timeout e repetição idempotente.
- Revogação do vínculo e tentativa posterior de uso.
- Registro e autenticação de múltiplas passkeys quando permitido pelo provedor e pelo contrato.

Testes de segurança devem ser isolados dos testes funcionais positivos, preservando evidências reproduzíveis.

## 8. Entregas incrementais

| Marco | Entrega | Critério de conclusão |
|---|---|---|
| E0 | Base do projeto e contratos | Apps executáveis localmente, documentação, infraestrutura e OAS versionadas |
| E1 | FAPI-BR + DCR/DCM | Cliente registrado no sandbox e autenticação OAuth funcional |
| E2 | Enrollment | Vínculo FIDO2 autorizado em sandbox |
| E3 | Pagamento JSR | Consentimento autorizado e Pix simulado iniciado |
| E4 | Console e hardening | Fluxos auditáveis, falhas tratadas e testes automatizados |
| E5 | Preparação offline | Interfaces prontas para transporte alternativo e aproveitamento da PoC 1A |

Cada entrega deverá ser validada antes do início da seguinte.

## 9. Fora do escopo inicial

Não implementar nesta fase:

- Comunicação NFC com POS.
- Pagamento com o smartphone offline.
- Liquidação financeira real.
- Servidor FIDO2 próprio para produção.
- Authorization Server próprio para produção.
- Pix Automático e pagamentos recorrentes.
- QR Pix dinâmico completo e verificação offline de JWS.
- Experiência final de um produto comercial.
- Certificação formal FAPI ou FIDO.

A arquitetura deverá permitir evolução posterior sem reescrita da camada de integração Open Finance.

## 10. Condições de qualidade

O agente de desenvolvimento deverá:

- Utilizar a especificação oficial como fonte dos contratos.
- Fixar versões das OAS, bibliotecas e dependências.
- Não inventar endpoints, scopes ou propriedades de mensagens.
- Diferenciar explicitamente requisitos normativos de escolhas internas de implementação.
- Não desabilitar validação TLS ou assinatura para fazer o sandbox funcionar.
- Não utilizar segredos reais em código-fonte, logs ou arquivos versionados.
- Implementar observabilidade e tratamento de erros desde a primeira entrega.
- Preservar a separação entre aplicativo, backend e integração Open Finance.
- Documentar qualquer incompatibilidade entre a especificação e o comportamento observado no sandbox.
- Manter um catálogo de requisitos com referência normativa, componente implementador, teste associado e resultado.

**Resultado final esperado:** uma wallet Android e um backend ITP operacional em sandbox, capazes de executar a Jornada Sem Redirecionamento até a iniciação de um Pix simulado, com suporte real aos mecanismos de segurança e registro exigidos pelo Open Finance Brasil.