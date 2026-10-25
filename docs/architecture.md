# Arquitetura de M01–M03

`apps/backend/src/config.ts` valida configuração antes de abrir portas; os caminhos dos arquivos são relativos ao JSON. Laboratório e sandbox usam configurações separadas. O modo sandbox rejeita origens de loopback e nunca carrega o simulador. Certificados, chaves, token administrativo, chave do cofre e URL do banco são referências a arquivos, não valores versionados.

O módulo `directory` lê o contrato PascalCase de participantes, filtra organizações ativas e associa organização, marca, AS e recursos publicados. O issuer do OIDC deve coincidir exatamente com o anunciado no Diretório. URLs de autorização, token, PAR, DCR, JWKS e recursos são descobertas; `mtls_endpoint_aliases` têm precedência. DCM usa a URI retornada pelo registro. Nenhuma URL de banco está embutida no cliente.

O cache é persistido em PostgreSQL, isolado por modo, com TTL configurável (1–3600 segundos). Metadados expirados não são servidos após falha remota. Há atualização explícita de participantes/OIDC, atualização OIDC nas operações DCM e atualização de JWKS para rotação. Erro de assinatura/`kid` pode renovar as chaves uma vez; não há loop de retentativas. SSA é obtido novamente e validado antes de registrar ou atualizar, com assinatura do Diretório, issuer, idade máxima de cinco minutos, organização/software, organização ativa, papel PAGTO ativo, scopes de iniciação autorizados, origens, callbacks e JWKS associados. As chaves de assinatura/criptografia e a chave pública BRCAC local devem corresponder às publicações indicadas no SSA.

## Transporte e JOSE

O transporte usa HTTPS, mTLS, TLS >=1.2 e valida cadeia e hostname. Suporta as duas cifras ECDHE-RSA/AES-GCM exigidas pelo FAPI e AES-GCM em TLS1.3; cache de sessão, tickets e renegociação são desabilitados no cliente. Somente origens HTTPS explicitamente autorizadas são acessíveis; não há redirecionamentos automáticos, downgrade para HTTP ou aceitação de URL de chave fornecida dentro de um JWT. Limites de tamanho e timeout absoluto se aplicam a cada chamada. Ao configurar sandbox, a lista de origens deve incluir os hosts de OIDC, mTLS, recursos e keystores descobertos; ela é uma escolha de defesa interna contra envio de certificados/credenciais para destinos indevidos.

O importador valida validade, chave privada correspondente, RSA >=2048 bits, cadeia com intermediárias, atributos normalizados de UID/organização e key usage. Transporte e assinatura usam pares distintos. Conforme Certificados 3.0, BRCAC identifica software e organização, e BRSeal identifica organização; `nonRepudiation` não é imposto pelo Open Finance. O modo sandbox exige bundle de CRLs assinado e vigente, aplicado tanto ao importador quanto ao TLS. O laboratório novo gera CRLs e uma folha revogada para teste. Não há atualização automática de CRLs, OCSP online ou certificação formal; a seleção das raízes ICP/Família AE e suas políticas vigentes deve ser confirmada pelo operador.

| Artefato | Assinatura e header | Claims e verificações |
|---|---|---|
| Client assertion | PS256, `kid`, `typ=JWT` | `iss=sub=client_id`, `aud=issuer do AS`, `iat/exp/jti`; validade de 60 s, replay |
| Request object | PS256, `kid`, `typ=oauth-authz-req+jwt` | `client_id/iss`, audiência do AS, `iat/exp/jti`, PKCE S256, `state/nonce` esperados, `acr` essential sem valor fixo, response mode fragment |
| Mensagem de recurso | PS256, `kid`, `typ=JWT` | organização em `iss`; `aud` é endpoint na requisição e ID da organização destinatária na resposta; `iat` ±60 s; `jti` UUID v4 com replay de 24 h por cliente |
| SSA | PS256, `kid` do Diretório | issuer configurado, `iat` e idade máxima de cinco minutos; `exp` quando presente |

Esses perfis são APIs reutilizáveis internas, não substituem validações por operação das OAS de Enrollments/Pagamentos (M05/M06). TTL de 60 segundos e tolerância de cinco segundos dos artefatos OAuth são escolhas internas; janela de `iat` e replay de recursos seguem FAPI-BR 2.2.1 §6.1. `state`/`nonce` aqui validam o artefato; a máquina de estados OAuth e a transação de callback pertencem a M04. `resourceRequest` e `resourceResponse` distinguem as audiências; `DirectoryService.verifyResource` valida respostas destinadas à própria ITP.

JWE usa RSA-OAEP + A256GCM, chave de criptografia separada, `kid` e `cty=JWT`. Após descriptografar, o chamador deve validar o JWS aninhado no perfil adequado. O serviço rejeita algoritmo não permitido, chave ambígua, referência de chave remota não confiável, token fora da janela e replay. A chave escolhida deve ser pública, RSA e compatível com `use/alg`. Recursos usam chaves anunciadas pelo Diretório; não se deriva uma URI a partir de `iss` não validado.

O helper de headers cria/valida correlação FAPI, data/IP do cliente e chave de idempotência quando a operação a exigir. O incremento não implementa operações de pagamento nem promete idempotência de pagamentos. O token probe é somente a verificação de autenticação exigida por M03; verifica TTL de 300–900 s e omite `openid` no grant client_credentials. No laboratório, uma chamada a `/lab/protected` demonstra assinatura do token, audiência, escopo e vinculação `cnf.x5t#S256` ao certificado; essa rota é explicitamente simulada.

## Persistência e falhas

PostgreSQL mantém metadados/cache em `itp_state`, replay atômico com expiração em `itp_replay` e eventos sanitizados em `itp_audit`. O registro é identificado por modo + organização ITP + software + organização detentora + AS. Bloqueios consultivos do PostgreSQL serializam o ciclo mesmo entre processos. As sessões de bloqueio são independentes do pool de consultas para não esgotá-lo durante IO de rede.

Os registros e todos os tokens retornados são criptografados com AES-256-GCM, IV aleatório e AAD vinculada à identidade do registro. A chave de 32 bytes fica fora do banco, em arquivo privado. Chaves privadas de certificados também ficam fora do banco. O backend não retorna tokens integrais no canal administrativo nem armazena o SSA no cache.

Um POST repetido recupera o registro existente ou faz PUT se origens, metadados do SSA, chave de assinatura ou certificado mudaram. DCR-BR 2.1 §6.1 proíbe o AS de rotacionar o token de gerenciamento. O laboratório padrão segue isso; uma falha explicitamente ativada nos testes permite exercitar um provedor RFC7592 divergente. Nesse caso, GET/PUT persistem o token novo e registram a incompatibilidade sem expor seu valor. O PUT envia os metadados completos conhecidos com as atualizações; DELETE exige confirmação 204 antes de remover o estado local.

`pending` é salvo antes do POST remoto. Timeout, resposta inválida, erro 5xx e falha de persistência após sucesso deixam `uncertain`; a próxima execução exige reconciliação, sem criar outro cliente. DCM também fica incerto durante a chamada porque o AS pode consumir/rotacionar o token até em GET. Esse comportamento privilegia evitar duplicação e reutilização insegura de credenciais.

Auditoria registra operação, resultado, status HTTP, duração e correlação; erros expostos são códigos estáveis. Não registra headers Authorization, payloads, SSA, chaves, URLs com query sensível nem respostas integrais do provedor. O console futuro poderá consultar esses eventos com controles de acesso e retenção adequados.
