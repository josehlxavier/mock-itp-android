# Sandbox, configuração e operação

O modo sandbox é um cliente de rede separado do laboratório. Não inicia o simulador, não fabrica SSA e não substitui erro remoto por dado local. Neste incremento, o modo está implementado, mas sem credenciais sem homologação no sandbox.

## Preparação

1. Confira os documentos oficiais fixados em `contracts.md` e as políticas/cadeias ICP vigentes para seus certificados.
2. Cadastre organização/software no Diretório. Cadastre callbacks do backend, origens Android e JWKS URI reais. O cliente OAuth confidencial é o backend (`application_type=web`); a wallet não guarda credenciais do AS.
3. Instale BRCAC, BRSeal e suas cadeias em arquivos PEM. Use pares separados de transporte/assinatura e outra chave RSA para descriptografia. As chaves devem estar em PKCS#8 PEM sem passphrase, protegidas pelo gerenciador de segredos/volume privado; os arquivos devem ter permissão 0600. Este incremento não integra HSM/KMS.
4. Prepare um trust bundle explícito contendo as raízes necessárias tanto para validar os certificados importados quanto os servidores HTTPS. A verificação inclui intermediárias. Forneça também `tls.crlFile` com CRLs assinadas e vigentes de todos os emissores envolvidos, inclusive dos servidores remotos; o modo sandbox exige esse arquivo e não tolera CRLs ausentes/expiradas. Mantenha o bundle atualizado por um processo operacional seguro. Não use `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized=false` ou bypass de assinatura.
5. Gere uma chave aleatória de 32 bytes, codificada em base64url, para o cofre, e um token administrativo aleatório com pelo menos 32 caracteres. Forneça a URL PostgreSQL por arquivo privado ou variável de ambiente. Faça backup seguro da chave do cofre junto com o banco.
6. Copie `config/sandbox.example.json` para um local privado, substitua **todos** os placeholders e ajuste referências relativas ao JSON. Os hosts `.invalid` são exemplos, não destinos reais. Configure `participantsUrl`, issuer exato do Diretório, sua JWKS, URL do SSA e `tokenFile` autorizado para acessar o Diretório. Alternativamente, remova `ssaUrl`/`tokenFile` e configure `ssaFile` com SSA recente e assinado.
7. Configure os scopes/grants/response types autorizados pela versão vigente e pelo SSA. Eles também são comparados com os valores anunciados pelo AS; não há scopes implícitos inventados para o sandbox.
8. Configure `allowedOrigins` com cada origem HTTPS necessária de Diretório, keystores, OIDC, mTLS e recursos. A política de saída da plataforma também deve permiti-las. Não cadastre origens arbitrárias retornadas por um JWT. Nenhuma nova credencial deve ser enviada pelo chat ou versionada.
9. Publique as chaves públicas onde a JWKS URI cadastrada no Diretório indicar. `GET /.well-known/jwks.json` fornece as chaves públicas da aplicação; a implantação deve disponibilizá-las por HTTPS ou carregar as chaves no keystore do Diretório. O laboratório espelha essa publicação em `/itp/jwks`. Não publique o conteúdo das chaves privadas.

Execute `ITP_CONFIG=/caminho/privado/config.json npm run dev`, ou a imagem compilada com volumes privados e PostgreSQL. O Compose fornecido é **somente para laboratório**, pois inclui o simulador. Não basta trocar `mode` no Compose para obter uma implantação sandbox.

Use a API administrativa para listar instituições, descobrir endpoints, registrar, consultar, atualizar e excluir. O token administrativo deve ser lido pelo cliente a partir do arquivo seguro. O smoke test fornecido é explicitamente local e não opera contra sandbox.

## Certificados e alterações do Software Statement

O laboratório gera uma CA raiz, uma intermediária e folhas válidas por sete dias. Reiniciar `lab:init` não substitui chaves ou configurações existentes. Para uma nova sessão de laboratório após expiração, crie um diretório separado com `LAB_DIR` e preserve os arquivos antigos/banco enquanto forem necessários; não destrua o cofre de um banco que ainda precisa ser acessado. A renovação automatizada de uma PKI existente não faz parte do helper.

Para rotação real, publique/cadastre previamente a nova chave/certificado no Diretório; mantenha a chave antiga publicada pelo tempo de validade dos artefatos já emitidos. Atualize referências locais, origens/callbacks quando necessário, e obtenha novo SSA. Reinicie o backend para validar e ativar o novo material. Faça POST no recurso administrativo de registro: ele detecta mudanças e usa **PUT DCM no cliente existente**, sem outro POST remoto. Execute o token probe depois da manutenção. O probe bloqueia uso de chaves/certificados alterados antes de DCM.

Durante um período de sobreposição, a JWKS externa deve conter ambas as chaves públicas; o backend só assina com a chave ativa configurada. Chaves privadas antigas nunca são publicadas. Os testes locais exercitam uma rotação coordenada de transporte, assinatura e origem Android mantendo o `client_id`. A chave BRCAC também deve estar publicada na JWKS de transporte referenciada pelo SSA.

A origem Android deve ser `android:apk-key-hash:` seguida do SHA-256, em base64url sem padding, do certificado de assinatura do APK. A mesma origem deve estar no Diretório/SSA (claim `origin` conforme DCR-BR 2.1) e na configuração; mudar pacote/certificado de assinatura exige atualizar esses cadastros e propagar pelo DCM. Digital Asset Links e o aplicativo Credential Manager pertencem à etapa Android.

## Reconciliação de resposta ambígua

Se houver `REGISTRATION_RECONCILIATION_REQUIRED`, não apague o estado nem tente registrar de novo. Consulte o provedor/administrador para recuperar o registro e seu token de gerenciamento atual por canal seguro. Grave a resposta de registro completa em arquivo privado, permissão 0600, fora do Git. Rode:

```bash
npm run reconcile -- ID_ORGANIZACAO_DETENTORA ID_AS /caminho/privado/registro-recuperado.json
```

O comando valida os metadados, consulta a URI de gerenciamento por mTLS com o token recuperado e persiste o novo token rotacionado, criptografado, antes de reativar o cliente. Ele só atua sobre estados incertos/pendentes e não emite novo POST DCR. Se o provedor não permitir recuperar o registro, é necessária uma decisão operacional de cancelamento no provedor antes de limpar o estado; não há exclusão automática desse bloqueio.
