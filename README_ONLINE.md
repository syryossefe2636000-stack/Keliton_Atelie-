# Keliton Ateliê 2.1 — pacote para publicação online

Este pacote foi preparado para rodar como **aplicação Node.js com HTTPS**. A interface do site foi preservada.

## O que foi preparado

- `index.html` continua como a interface principal.
- `server.js` continua responsável por login, sessão, produtos, músicas e Gmail.
- Endpoint `/health` para verificar se o servidor está funcionando.
- `Procfile` para hosts que iniciam aplicações Node automaticamente.
- `.node-version` com Node 20.
- `package.json` com comando de verificação corrigido.
- `.env.example` mantido como modelo de configuração.
- `.gitignore` impede publicar `.env`, sessões, usuários e estado privado.

## Importante: não use GitHub Pages para esta versão

O projeto possui backend (`server.js`). Por isso, o GitHub Pages sozinho não executa o servidor. Para colocar **todas as funções** online, publique este projeto em um serviço que execute Node.js (por exemplo, Render ou Railway) e conecte o repositório do GitHub.

## Variáveis obrigatórias

Configure no serviço de hospedagem:

- `PUBLIC_BASE_URL` = endereço HTTPS final do site
- `COOKIE_SECURE=true`
- `NODE_ENV=production`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `FACEBOOK_APP_ID`
- `FACEBOOK_APP_SECRET`
- `ADMIN_EMAIL`
- `ENCRYPTION_KEY_HEX` = 64 caracteres hexadecimais

Nunca coloque esses valores dentro do `index.html` ou publique o arquivo `.env`.

## Comando de execução

```bash
npm start
```

Health check:

```text
/health
```

## OAuth

Depois de obter o domínio HTTPS definitivo, atualize no Google Cloud:

`https://SEU-DOMINIO/auth/google/callback`

E no Meta/Facebook:

`https://SEU-DOMINIO/auth/facebook/callback`

Também atualize `PUBLIC_BASE_URL` para o domínio real.

## Persistência

O servidor grava dados em `data/state.json`, `data/users.json`, `data/sessions.json` e arquivos de música em `data/music/`. Em uma hospedagem com armazenamento efêmero, esses dados podem ser perdidos após reinicialização/deploy. Para uso real, escolha hospedagem com volume/disco persistente ou migre esses dados para um banco/armazenamento persistente.
