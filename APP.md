# Keliton Ateliê — App

Esta versão transforma o site em um **Web App instalável (PWA)**, preservando a interface existente.

## Como instalar no Android
1. Publique o projeto em um domínio com HTTPS.
2. Abra o endereço no Chrome do celular.
3. Use **Instalar aplicativo** / **Adicionar à tela inicial**.
4. O app abrirá em modo próprio, sem a barra normal do navegador.

## O que já está preparado
- Ícone e nome do aplicativo.
- Manifesto PWA.
- Modo tela cheia/standalone.
- Cache básico para abertura mais rápida.
- Estrutura de login Google/Facebook e Gmail do administrador permanece no projeto.

## Próxima etapa para APK nativo
Se quiser gerar um APK/AAB de loja, esta mesma pasta pode ser empacotada com Capacitor e aberta no Android Studio. As credenciais OAuth devem ser configuradas no ambiente de produção; nunca coloque segredos reais dentro do app.
