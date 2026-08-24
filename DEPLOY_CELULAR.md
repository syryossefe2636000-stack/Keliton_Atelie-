# PUBLICAÇÃO DO KELITON ATELIÊ — LOGIN GOOGLE/FACEBOOK REAL

## IMPORTANTE
Esta versão precisa de um servidor Node.js. GitHub Pages hospeda arquivos estáticos e não executa `server.js`. Por isso, NÃO use GitHub Pages para esta versão se quiser login Google/Facebook real.

O pacote já contém:
- `server.js` com OAuth Google/Facebook e sessões por cookie;
- `index.html` preservando a interface;
- `Procfile` e `render.yaml` para hospedagem Node;
- `/health` para teste do servidor;
- `.env.example` com os nomes das variáveis necessárias.

## No celular — opção recomendada
1. Crie uma conta no Render.
2. Crie um Web Service a partir do repositório GitHub.
3. Use o branch `main`.
4. Build Command: `npm install`
5. Start Command: `npm start`
6. Health Check Path: `/health`
7. Depois que o Render fornecer o domínio HTTPS, coloque esse endereço em `PUBLIC_BASE_URL`.

## Google
No Google Cloud, crie um cliente OAuth para aplicação Web e cadastre exatamente:
`https://SEU-DOMINIO/auth/google/callback`

Preencha no servidor:
- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET

## Facebook
No Meta for Developers, configure o login do Facebook e cadastre exatamente:
`https://SEU-DOMINIO/auth/facebook/callback`

Preencha no servidor:
- FACEBOOK_APP_ID
- FACEBOOK_APP_SECRET

## Conta administradora
`ADMIN_EMAIL` deve ser o e-mail Google que terá acesso administrativo.

## Criptografia
Crie uma chave aleatória de 32 bytes e coloque o resultado hexadecimal (64 caracteres) em `ENCRYPTION_KEY_HEX`.

## Depois
Abra o domínio HTTPS do Render e toque em:
Minha Conta → Continuar com Google / Facebook.

O navegador será enviado ao provedor, depois voltará para `/auth/.../callback` e a sessão será criada no servidor.

## NÃO faça
- Não coloque `GOOGLE_CLIENT_SECRET`, `FACEBOOK_APP_SECRET` ou `ENCRYPTION_KEY_HEX` dentro do `index.html`.
- Não publique um `.env` real no GitHub.
- Não tente executar `server.js` pelo GitHub Pages.
