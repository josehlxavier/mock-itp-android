# Contratos, versões e fontes

O plano estabelece DCR-BR **2.1.0**, FAPI-BR **2.2.1** e Padrão de Certificados **3.0** como alvos. As regras implementadas foram conferidas contra essas versões, o que **não equivale a certificação ou homologação**. Enrollments 2.3.0 e Pagamentos 5.0.0 aparecem apenas como metadados simulados de descoberta; os clientes dessas APIs pertencem a M05/M06.

As páginas oficiais publicadas no espaço `OF` do portal Atlassian foram obtidas pela API pública, com ID, revisão e SHA-256 fixados em `contracts/sources.json`. O conteúdo storage HTML original está em `contracts/vendor`, com atribuição preservada. Referências atuais:

| Documento | Página oficial / revisão |
|---|---|
| DCR-BR 2.1.0 | 1334116369 / 2 |
| FAPI-BR 2.2.1 | 1957625902 / 3 |
| Certificados 3.0 | 2127298593 / 1 |

Também foram preservadas referências dos repositórios oficiais `OpenBanking-Brasil/specs-seguranca` e `OpenBanking-Brasil/specs-directory`, com commits e checksums exatos:

| Referência acessível | Versão/snapshot | Uso |
|---|---|---|
| Diretório, `swagger_participants.yaml` | 1.1.0, commit `fadd5e2c90f0b0d0febe2d209cd60f5bf92af21c` | Estrutura de organizações, ASs, marcas e recursos |
| DCR/DCM OAS | 2.0.1, commit `9bb9b2979f57638ad53ec3b8ed3d1ec084de2dda` | Registro JSON, respostas, campos obrigatórios, manutenção |
| DCR-BR perfil | ID3 no mesmo commit | Precedência dos aliases mTLS, SSA, JWKS referenciada e correspondência de metadados |
| FAPI-BR perfil | ID3 no mesmo commit | Separação de papéis e requisitos de segurança |
| Certificados | ID2 no mesmo commit | BRCAC (UID de software) e assinatura (UID de organização), cadeia e key usage |

As atribuições e avisos dos documentos originais foram mantidos. A cópia original do plano recebido está em `docs/plan.md`.

Referências complementares usadas no desenho:

- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591): Dynamic Client Registration, seções 2–3.
- [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592): leitura, atualização completa, exclusão e rotação do registration access token.
- [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523): autenticação de cliente por JWT.
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705): mTLS, tokens vinculados a certificados e aliases.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [7516](https://www.rfc-editor.org/rfc/rfc7516) e [7519](https://www.rfc-editor.org/rfc/rfc7519): JWS, JWE e JWT.
- [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101): request object e `oauth-authz-req+jwt`.
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) e [Registration](https://openid.net/specs/openid-connect-registration-1_0.html).
- Diretório privado: `OpenBanking-Brasil/specs-directory/openapi.yaml`, no commit acima, confirma GET de Software Statement Assertion, com resposta `application/jwt` ou JSON string. A implementação usa a variante JWT.

## O que os testes de contrato comprovam

Os checksums comprovam quais documentos foram utilizados. AJV valida a resposta DCR do laboratório contra o schema `ClientRegistrationResponseSuccess` da OAS 2.0.1, incluindo o caso negativo sem token de gerenciamento. Os parsers em runtime validam o subconjunto consumido da resposta de participantes/OIDC e os campos críticos de segurança do DCR/DCM. O perfil DCR-BR 2.1.0 aponta explicitamente para essa OAS 2.0.1: são versões de documentos diferentes, não uma suposição de que a OAS seja 2.1.0. Isso não equivale a executar uma suíte de conformidade oficial ou validar todas as operações das OAS futuras.

## Diferenças reconciliadas e limites

A primeira tentativa de acessar Atlassian/API GitHub foi bloqueada por 403. Após mudança no estado de rede, a API GitHub ficou acessível; o link antigo de Segurança retornou página removida/404. A busca pública do Confluence localizou as versões-alvo publicadas, que foram consultadas e fixadas. O rascunho de rede conserva os presets e adiciona `openfinancebrasil.atlassian.net`, `api.github.com`, `openid.net` e `www.rfc-editor.org`. Esse fato não é uma declaração de publicação do ambiente.

A reconciliação resultou nestas regras implementadas:

- FAPI-BR 2.2.1 §6.1: `iat` de recursos ±60 s, `jti` UUID v4, replay de 24 horas por cliente, audiência da resposta igual ao ID da organização destinatária; requisições usam a URI do endpoint. Replay retorna 403 e falha criptográfica de recurso usa `BAD_SIGNATURE`.
- FAPI-BR 2.2.1 §§5.1/5.2/6.4: PAR obrigatório no perfil, request object com `acr` essential sem valor fixo, tokens de 300–900 s e desativação de retomada de sessão/renegociação TLS no cliente.
- DCR-BR 2.1 §6.1: o AS não deve rotacionar o registration access token. A rotação em laboratório existe apenas como falha explícita para testar tolerância e auditoria de incompatibilidades.
- DCR-BR 2.1 §§7/8: papel PAGTO ativo, scopes de iniciação autorizados, chave de criptografia publicada e identidade de software/organização. A BRCAC deve corresponder à JWKS de transporte indicada no SSA.
- O plano chama as origens Android de `software_origin_uris`, mas o exemplo oficial de SSA em DCR-BR 2.1 usa a claim **`origin`**. A implementação utiliza `androidOrigins` na configuração, valida contra `SSA.origin` e propaga o SSA atualizado por DCM. Não inventa o campo `software_origin_uris` no payload DCR: ele não está definido na OAS referenciada. Esse é um ajuste explícito do nome lógico do plano ao contrato oficial.
- Certificados 3.0 §§5.6/5.7: revogação verificada com CRLs fornecidas, BRSeal com UID da organização, BRCAC com UID de software/OrganizationId, atributos normalizados e digitalSignature. Não se exige nonRepudiation para toda BRSeal, pois o documento remete esse uso ao perfil ICP aplicável.

Permanecem pendentes as credenciais e os testes de interoperabilidade contra sandbox real. A instalação deve fornecer raízes/políticas ICP-Brasil apropriadas, CRLs vigentes, certificados corretamente cadastrados e uma publicação real de JWKS. Não há atualização automática de CRL, OCSP online ou certificação formal. Nenhuma incompatibilidade de AS real foi observada: **nenhum AS externo foi acessado**. As incompatibilidades exercitadas são falhas explícitas do simulador.
