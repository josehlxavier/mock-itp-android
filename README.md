# Open Finance Wallet Simulator

Primeiro incremento do plano: **M01 (Diretório e descoberta), M02 (segurança e criptografia) e M03 (DCR/DCM)**. Backend Node.js 24, TypeScript, Fastify e PostgreSQL; laboratório HTTPS com CA própria, Diretório e dois Authorization Servers simulados. Não há aplicação Android nesta etapa: ela pertence aos incrementos seguintes.

O ciclo local funciona com criptografia e mTLS reais, com as regras implementadas conferidas contra as referências oficiais de DCR-BR 2.1.0, FAPI-BR 2.2.1 e Certificados 3.0. **A integração ao sandbox e a conformidade formal ainda não foram homologadas.** As fontes fixadas e pendências estão em [contratos](docs/contracts.md) e no [catálogo de requisitos](docs/requirements.md).

## Executar em laboratório

Requisitos: Node **24.19.0**, npm, OpenSSL 3+, Docker com Compose v2. Execute na raiz do repositório:

```bash
npm ci --ignore-scripts
npm run lab:init
docker compose up -d --build --wait
npm run smoke
```

`lab:init` cria certificados, chaves e configuração em `.local/`, ignorado pelo Git, com arquivos de segredo privados. Não sobrescreve uma configuração existente. Os certificados válidos do laboratório expiram em sete dias; os certificados com prefixo `expired-` são exclusivamente fixtures negativas. A origem Android local é um identificador de teste, sem associação com um APK real.

As portas 3000 (backend), 9443 (laboratório mTLS) e 5432 (PostgreSQL) ficam restritas ao loopback. O smoke test faz descoberta → DCR → registro repetido → token → DCM GET/PUT → token → DELETE, verificando as respostas. Ele usa a credencial administrativa pelo arquivo e não imprime tokens.

Neste ambiente de nuvem, se o build padrão falhar por DNS/proxy do Docker:

```bash
npm run image:build:cloud
docker compose up -d --no-build --wait
npm run smoke
```

O helper reutiliza o proxy e a CA existentes somente no build. Não desativa TLS nem validação de pacotes. `docker compose stop` para os serviços; `docker compose up -d --no-build --wait` os retoma. Preserve `.local/` e o volume PostgreSQL juntos: perder a chave do cofre impede ler as credenciais persistidas.

## Desenvolvimento e testes

```bash
npm run typecheck
npm test                  # funcionais, segurança isolada e contratos
npm run test:postgres     # PostgreSQL real; schemas temporários isolados
npm run build
```

Os testes normais não dependem de Docker nem do sandbox: sobem servidores HTTPS reais em portas temporárias e usam um double de armazenamento. A suíte PostgreSQL valida atomicidade, concorrência e persistência entre runtimes/conexões independentes. Ela usa `TEST_DATABASE_URL`, ou `.local/database.url`. A CI executa ambas.

Para editar o backend com reload manual, pare os containers `backend` e `lab`, mantenha o PostgreSQL ativo e execute `npm run lab` e `npm run dev` em terminais separados. A configuração padrão é `.local/config.json`; `ITP_CONFIG` seleciona outra. `DATABASE_URL_FILE` ou `DATABASE_URL` substituem a URL de banco da configuração.

## Interfaces

`GET /health` informa o modo e verifica o banco. `GET /.well-known/jwks.json` publica apenas chaves públicas. Todas as rotas `/admin` exigem `Authorization: Bearer` com o segredo de `adminTokenFile`. Não exponha essas rotas na Internet sem um gateway HTTPS e controles de acesso.

| Método | Rota | Operação |
|---|---|---|
| GET | `/admin/environment` | Ambiente e validade/fingerprints dos certificados |
| GET | `/admin/software-statement` | Claims selecionados do SSA validado; sem o JWT |
| GET | `/admin/institutions` | Organizações ativas, marcas e ASs |
| POST | `/admin/metadata/refresh` | Invalidar/atualizar cache de participantes |
| GET | `/admin/institutions/:org/servers/:as/discovery` | OIDC e recursos anunciados |
| POST | mesma base + `/discovery/refresh` | Atualizar participantes e OIDC do AS |
| POST | `/admin/institutions/:org/servers/:as/registration` | Registrar ou manter o cliente existente |
| GET/PUT/DELETE | mesma rota `/registration` | Consultar/atualizar/excluir no AS |
| GET | mesma base + `/registration/local` | Estado local sanitizado |
| POST | mesma base + `/token-probe` | Validar `client_credentials`; retorna resumo sem token |

No laboratório, os pares são `bank-a`/`as-a` e `bank-b`/`as-b`. O console web e a orquestração OAuth interativa não fazem parte deste incremento.

Leia [arquitetura e segurança](docs/architecture.md), [operação do sandbox e rotações](docs/sandbox.md) e o [plano original](docs/plan.md).
