# Cadeia de Custódia de Evidências: demo do MVP

Protótipo navegável do MVP de cadeia de custódia (Desafio 4). Roda inteiro no navegador, em uma única página (`index.html`), sem backend.

## O que dá para testar

- Cadastro de evidência com ocorrência, lacre do Instituto ou externo e pergunta de transporte.
- Encaminhamento, recebimento, análise, armazenamento e devolução, com as regras de setor e perfil (troque o usuário no menu lateral).
- Rompimento de lacre e bloqueio da evidência até um novo lacre (RF07b).
- Hash chain SHA-256 real, verificação de integridade e simulação de adulteração.
- Lotes de lacres com QR code (como administrador).
- Aba de requisitos com os RF/RNF levantados. Passe o mouse sobre cada funcionalidade para ver o ID do requisito.

## Limitações da demo

- Os dados ficam só no navegador de quem abre (localStorage). "Restaurar dados de exemplo" volta ao início.
- Login, câmera, GPS, impressão e PDF são simulados.
- O hash é calculado no navegador; no sistema real ele fica no backend (RNF04).

## Banco de dados

A pasta `database/` tem o esquema PostgreSQL do sistema real (`schema.sql`) e os testes (`testes.sql`). Ela não é publicada na Vercel.

## Rodar localmente

Abra `index.html` no navegador, ou sirva a pasta:

```
npx serve .
```
