# Evidências da entrega M01–M03

Validação realizada no ambiente de nuvem, com Node 24.19.0, Docker/Compose e PostgreSQL 17.6. Todos os fluxos funcionais abaixo usam o laboratório local, com PKI gerada durante os testes e HTTPS/mTLS reais.

| Verificação | Resultado |
|---|---|
| TypeScript (`npm run typecheck`) | Passou |
| Funcionais (`npm run test:functional`) | 5 testes passaram |
| Segurança isolada (`npm run test:security`) | 32 testes passaram |
| Contratos (`npm run test:contract`) | 2 testes passaram |
| PostgreSQL real (`npm run test:postgres`) | 2 testes passaram |
| Build TypeScript (`npm run build`) | Passou |
| Build Docker via proxy/CA existentes (`npm run image:build:cloud`) | Passou; verificações mantidas |
| Compose PostgreSQL + laboratório + backend | Serviços iniciados e healthchecks passaram |
| Smoke funcional (`npm run smoke`) | Passou: descoberta, registro, repetição, autenticação, GET/PUT, nova autenticação e DELETE |
| Reiniciar backend e repetir smoke | Passou |
| Auditoria npm de dependências de runtime | Nenhuma vulnerabilidade conhecida reportada no momento da execução |

São **41 testes automatizados**, sem skips, além dos smoke tests e builds. A suíte PostgreSQL usa schemas temporários e conexões independentes. O teste de restauração conserva o mesmo `client_id` e suporta token DCM rotacionado em um teste explícito de provedor divergente. O laboratório padrão não rotaciona esse token, conforme DCR-BR 2.1. Os negativos de mTLS incluem ausência de certificado, cadeia/hostname inválidos e certificados expirados/revogados em handshakes reais. O replay de recursos é validado por 24 h e atravessa endpoints, conforme FAPI-BR 2.2.1.

O primeiro build Docker padrão encontrou falha de DNS no namespace do build. O helper de nuvem corrige a conectividade usando o proxy já configurado, encaminhado como argumento predefinido do Docker, e a CA como secret de build. A imagem executa como usuário `node`; os segredos do laboratório são montados apenas em runtime e não entram no contexto da imagem.

Fora desta validação local: sandbox real, homologação das versões normativas atuais, aplicativo Android, Enrollments/Pagamentos e callbacks/jornadas OAuth. O resultado da CI remota deve ser consultado nas verificações do PR. Este relatório não comprova publicação do ambiente ou implantação externa.

As instruções de execução e todos os arquivos da implementação estão no repositório. `.local/`, `node_modules/`, `dist/` e os volumes Docker são estado local ignorado. O rascunho das configurações de rede é descrito em `contracts.md`; salvar um rascunho não comprova aplicação da rede ou publicação do ambiente.
