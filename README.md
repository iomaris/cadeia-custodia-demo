# Cadeia de Custódia de Evidências: demo do MVP

Protótipo navegável do MVP de cadeia de custódia (Desafio 4). Roda inteiro no navegador, em uma única página (`index.html`), sem backend.

## O que dá para testar

- Cadastro de evidência com ocorrência, lacre do Instituto ou externo e pergunta de transporte.
- Encaminhamento, recebimento, análise, armazenamento e devolução, com as regras de setor e perfil (troque o usuário no menu lateral).
- Rompimento de lacre e bloqueio da evidência até um novo lacre (RF07b).
- Hash chain SHA-256 real, verificação de integridade e simulação de adulteração.
- Lotes de lacres com QR code (como administrador).
- Aba de requisitos com os RF/RNF levantados e as colunas do banco que atendem cada um.
- Aba "Banco de dados" com as 13 tabelas e 128 colunas, o tipo, se é obrigatória, a descrição e os requisitos de cada coluna.
- Passe o mouse sobre qualquer funcionalidade ou campo para ver os IDs dos requisitos e as colunas do banco (`tabela.coluna`) envolvidas.

## Limitações da demo

- Os dados ficam só no navegador de quem abre (localStorage). "Restaurar dados de exemplo" volta ao início.
- Login, câmera, GPS, impressão e PDF são simulados.
- O hash é calculado no navegador; no sistema real ele fica no backend (RNF04).

## Banco de dados

A pasta `database/` tem o esquema PostgreSQL do sistema real (`schema.sql`) e os testes (`testes.sql`, 40 casos). Cada tabela e coluna tem um comentário no próprio banco com a descrição e os requisitos atendidos: no psql, `\d+ custodia.evidencia`. Listas fixas (perfil, situação, tipo...) são `varchar(30)` com restrição `CHECK`, textos com limite natural são `varchar(n)` e datas são `timestamp with time zone`; o dicionário de dados explica o porquê de cada tipo. A pasta não é publicada na Vercel.

## Rodar localmente

Abra `index.html` no navegador, ou sirva a pasta:

```
npx serve .
```
