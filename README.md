# LAWLY — Contas e licenças

Servidor de autenticação e painel administrativo para o `LawlyPainel.exe` 1.9.0. O admin usa a mesma linguagem visual do painel: Inter, cinza e preto, transições suaves, cards, modais e notificações animadas.

## Publicar no GitHub

Suba **o conteúdo desta pasta `server`** para um repositório. O pacote `LAWLY-Servidor.zip` já contém somente esses arquivos, sem contas, senhas, chaves, banco de dados ou configurações pessoais.

O GitHub armazena o código. O processo Python precisa rodar em uma hospedagem com HTTPS e armazenamento persistente. Não funciona como site estático do GitHub Pages.

### Variáveis do servidor

| Nome | Uso |
| --- | --- |
| `ADMIN_SECRET` | Chave administrativa aleatória, com pelo menos 24 caracteres. Obrigatória; nunca vai no código ou no `.exe`. |
| `PUBLIC_URL` | Origem pública HTTPS, sem caminho final. Usada para conferir a origem do admin e proteger seu cookie. |
| `DATABASE_PATH` | Caminho do SQLite em um disco persistente. Ex.: `/data/licenses.db`. |
| `HOST` | `0.0.0.0` na hospedagem; `127.0.0.1` em desenvolvimento. |
| `PORT` | Porta HTTP interna. Padrão: `8080`. |

Gere sua chave no seu terminal: `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Configure o resultado no gerenciador de variáveis da hospedagem. Não o publique no GitHub.

### Executar com Python

Requer Python 3.12 ou superior:

```text
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

No PowerShell, defina `ADMIN_SECRET` e, em produção, `PUBLIC_URL` e `DATABASE_PATH`. Depois execute:

```text
.venv\Scripts\python app.py --host 127.0.0.1 --port 8080
```

No Linux, use `.venv/bin/python`. Acesse `/admin`, entre com `ADMIN_SECRET` e crie uma conta com o produto **LAWLY**. Senhas não são exibidas novamente no admin.

### Executar com Docker

```text
docker build -t lawly-license .
docker volume create lawly-data
docker run --name lawly-license --env-file .env -p 8080:8080 --mount type=volume,source=lawly-data,target=/data lawly-license
```

Copie `.env.example` para `.env` e preencha os valores antes de executar. Coloque um proxy HTTPS à frente do serviço. O container roda como usuário sem privilégios. Mantenha **um único processo/réplica** usando esse banco SQLite. Se a hospedagem descartar o disco a cada deploy, as contas também serão descartadas: configure o volume persistente antes de usar com clientes.

## Conectar o painel Windows

Na mesma pasta do executável, acrescente ao `painel.ini`:

```ini
[Login]
Servidor=https://seu-servidor.example
```

Use somente a URL base, sem `/auth`. O exemplo acima deve ser substituído pela URL real após publicar. O cliente usa HTTPS, valida o certificado e rejeita redirecionamentos. HTTP é aceito exclusivamente em `localhost`, `127.0.0.1` e `::1` para testes locais. O endereço é configurável; não é necessário recompilar para alterá-lo.

A senha é validada no servidor, com PBKDF2-HMAC-SHA256, salt aleatório de 32 bytes e 600.000 iterações. Nenhuma conta ou senha fica embutida no `.exe`. O nome de usuário permanece no banco para o administrador gerenciar a conta; a senha permanece apenas como hash e salt.

“Lembrar senha” salva **usuário e senha criptografados com DPAPI**, no mesmo `painel.ini`. O blob está vinculado ao endereço do servidor e normalmente só pode ser aberto pelo mesmo usuário do Windows no mesmo computador. Mudar a URL não envia automaticamente o acesso salvo para outro servidor. Desmarcar a opção apaga o blob. A configuração de aparência e das macros continua na seção `[Painel]`.

## Licenças e sessões

- Criação de contas, produtos livres, prazo por dias/data ou vitalício.
- Pausa com congelamento do tempo, retomada, edição, revogação, exclusão, redefinição de senha e reset da máquina.
- Identificação de máquina: SHA-256 do identificador do Windows com contexto LAWLY. O identificador original não é enviado.
- Uma sessão por conta; a sessão dura até 120 segundos sem renovação. Um novo login do mesmo cliente rotaciona o token e invalida o anterior.
- O cliente renova a validação a cada 30 segundos, ou antes se a licença estiver perto de expirar. Uma pausa/revogação pode levar até a próxima verificação para bloquear o painel. Falha de validação ou de rede também bloqueia as funções.
- Antes de autenticar, as macros e a mira permanecem bloqueadas. O atalho de Correr também não funciona na tela de login.
- “Encerrar sessão”, em Ajustes, devolve o aplicativo ao login e revoga a sessão atual. Se fechar abruptamente, a sessão libera após o prazo de até 120 segundos; o mesmo cliente pode entrar novamente imediatamente.
- O admin usa cookie HttpOnly/SameSite, não armazena a chave no localStorage e não coloca segredos em URLs. A API administrativa também aceita `X-Admin-Secret` para ferramentas autorizadas.
- Backups exportados incluem hashes de senha e vínculos de máquina: guarde-os como dados privados. O arquivo exportado não contém senhas em texto aberto nem tokens de sessão.

O vínculo de máquina e o bloqueio são mecanismos de licença em software; não tornam um executável impossível de modificar. O estado da licença é decidido no servidor, não em hashes de senha embutidos no cliente.

## API

`POST /auth` recebe `username`, `password`, `hwid` (64 caracteres hex), `client_id` (64 hex) e `product`. Responde com `ok`, `code`, `reason`, `permissions`, `session_token`, `expires_in` e `expires_at`. Para renovar, envie `session_token` no lugar de `password`. Para sair, envie a mesma identificação/token com `logout: true`.

Admin: `POST /admin/login`, `POST /admin/logout`, `GET/POST /admin/users`, `GET /admin/stats`, `GET /admin/backup` e `POST /admin/users/{pause,resume,revoke,hwid-reset,password,edit,delete}`. Use `username` no corpo das ações. Autenticação administrativa é obrigatória para ler ou alterar contas.

## Testes

```text
python -m unittest discover -s tests -v
```

Os testes usam banco temporário e cobrem credenciais, permissão, validade, vínculo de máquina, sessão única, renovação, rotação, saída, pausa, retomada, revogação, troca de senha, persistência, autorização administrativa, origem, entradas inválidas e limite de requisições.
