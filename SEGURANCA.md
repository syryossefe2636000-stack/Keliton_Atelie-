# Keliton Ateliê — Segurança

Esta versão mantém a interface existente e reforça o backend.

## Obrigatório em produção
Configure no provedor Node:
- PUBLIC_BASE_URL (HTTPS)
- NODE_ENV=production
- COOKIE_SECURE=true
- ADMIN_EMAIL
- ADMIN_PASSWORD_HASH (SHA-256 hexadecimal, 64 caracteres)
- ENCRYPTION_KEY_HEX (64 caracteres hexadecimais)

Google/Facebook são opcionais até serem configurados.

## Importante
Não publique `.env`, segredos OAuth, hashes/chaves reais ou tokens no GitHub.
A senha administrativa não é armazenada em texto puro.
As rotas de alteração de produtos, vendedor e música exigem sessão administrativa.
A biometria usa WebAuthn/passkey e depende de HTTPS + backend Node ativo.

## GitHub Pages
GitHub Pages pode continuar servindo uma versão estática, mas não executa `server.js`. Para login real, administração segura, Gmail e WebAuthn, publique o projeto Node em um serviço compatível e configure o domínio HTTPS final em PUBLIC_BASE_URL.
