# Keliton Ateliê — versão corrigida para publicação

## Correção principal
O servidor agora cria automaticamente a pasta `data` antes de criar os arquivos de sessão, usuários e biometria. Isso evita que o backend encerre na inicialização em uma hospedagem nova — o que impedia o acesso ao administrador.

A interface do site foi preservada.

## Publicação
Esta versão é para uma hospedagem que execute Node.js (por exemplo, Render/Railway ou outro serviço Node). GitHub Pages sozinho não executa `server.js` nem as rotas `/api`.

O projeto já contém `Procfile` e `render.yaml`.

### Comando
`npm install`

`npm start`

O servidor usa a porta definida por `PORT`.

### Variáveis de produção
Configure no serviço de hospedagem:
- `PUBLIC_BASE_URL` — endereço HTTPS final do site
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `ADMIN_EMAIL` — conta Google que será administradora
- `ADMIN_PASSWORD_HASH` — SHA-256 da senha administrativa
- `ENCRYPTION_KEY_HEX` — 64 caracteres hexadecimais
- `COOKIE_SECURE=true`
- `NODE_ENV=production`

Facebook é opcional (`FACEBOOK_APP_ID` e `FACEBOOK_APP_SECRET`).

### Senha administrativa da versão atual
A versão de demonstração mantém a senha inicial já existente no projeto: `tomdiversos`.

**Antes de colocar o site em produção, troque essa senha** configurando `ADMIN_PASSWORD_HASH` no serviço de hospedagem.

### Biometria
Depois de entrar no administrador pelo menos uma vez, use `Segurança de acesso` → `Cadastrar facial para acesso ao administrador`. A biometria exige HTTPS e o backend Node ativo.

### Firebase
A configuração do Firebase Web não substitui o backend OAuth deste projeto. O login Google do servidor usa `GOOGLE_CLIENT_ID` e `GOOGLE_CLIENT_SECRET`, com o callback `/auth/google/callback` configurado no Google Cloud.

Não publique `.env`, senhas, client secrets ou chaves privadas.
