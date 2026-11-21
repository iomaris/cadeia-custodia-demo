-- =============================================================================
-- Testes do esquema (rodar em um banco de teste, depois do schema.sql):
--   psql "$DATABASE_URL_TESTE" -v ON_ERROR_STOP=1 -f testes.sql
-- Cada teste imprime OK; qualquer falha interrompe o script com erro.
-- =============================================================================
SET search_path = custodia, public;
\set QUIET on
\pset tuples_only on

-- Ajudante: executa um comando e exige que ele falhe com uma mensagem esperada.
CREATE OR REPLACE FUNCTION pg_temp.espera_erro(p_sql text, p_trecho text, p_nome text) RETURNS text
LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    EXECUTE p_sql;
  EXCEPTION WHEN others THEN
    IF position(lower(p_trecho) IN lower(SQLERRM)) > 0 THEN
      RETURN 'OK  ' || p_nome;
    END IF;
    RAISE EXCEPTION 'FALHOU %: erro inesperado: %', p_nome, SQLERRM;
  END;
  RAISE EXCEPTION 'FALHOU %: o comando deveria ter sido recusado', p_nome;
END $$;
CREATE OR REPLACE FUNCTION pg_temp.ok(p_cond boolean, p_nome text) RETURNS text
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT coalesce(p_cond, false) THEN RAISE EXCEPTION 'FALHOU %', p_nome; END IF;
  RETURN 'OK  ' || p_nome;
END $$;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA pg_temp TO custodia_app;

-- ---------------------------------------------------------------- dados base
INSERT INTO setor (id, nome) VALUES
  ('00000000-0000-0000-0000-0000000000a1', 'Recepção'),
  ('00000000-0000-0000-0000-0000000000a2', 'Laboratório de Balística'),
  ('00000000-0000-0000-0000-0000000000a3', 'Depósito');
INSERT INTO usuario (id, nome, matricula, email, senha_hash, perfil, setor_id) VALUES
  ('00000000-0000-0000-0000-0000000000b1', 'Ana Ribeiro',    '1001', 'ana@ic.gov.br',    '$2b$12$abcdefghijklmnopqrstuv', 'administrador', '00000000-0000-0000-0000-0000000000a1'),
  ('00000000-0000-0000-0000-0000000000b2', 'Rafael Souza',   '2014', 'rafael@ic.gov.br', '$2b$12$abcdefghijklmnopqrstuv', 'perito',        '00000000-0000-0000-0000-0000000000a1'),
  ('00000000-0000-0000-0000-0000000000b3', 'Júlia Farias',   '3120', 'julia@ic.gov.br',  '$2b$12$abcdefghijklmnopqrstuv', 'normal',        '00000000-0000-0000-0000-0000000000a2'),
  ('00000000-0000-0000-0000-0000000000b4', 'Carlos Menezes', '2031', 'carlos@ic.gov.br', '$2b$12$abcdefghijklmnopqrstuv', 'perito',        '00000000-0000-0000-0000-0000000000a2');

-- A partir daqui, tudo roda com o perfil da API.
SET ROLE custodia_app;

-- ---------------------------------------------------------------- usuários e setores
SELECT pg_temp.espera_erro($$INSERT INTO usuario (nome, matricula, email, senha_hash, setor_id) VALUES ('Xavier Lima', '1001', 'x@ic.gov.br', '$2b$12$a', '00000000-0000-0000-0000-0000000000a1')$$,
  'usuario_matricula_uk', 'matrícula duplicada é recusada');
SELECT pg_temp.espera_erro($$INSERT INTO usuario (nome, matricula, email, senha_hash, setor_id) VALUES ('Xavier Lima', '9', 'x@ic.gov.br', 'senha123', '00000000-0000-0000-0000-0000000000a1')$$,
  'senha_hash', 'senha em texto puro é recusada');
SELECT pg_temp.espera_erro($$INSERT INTO setor (nome) VALUES ('recepção ')$$, 'setor_nome_uk', 'setor com nome repetido é recusado');
SELECT pg_temp.espera_erro($$INSERT INTO setor (nome) VALUES (repeat('a', 121))$$, 'value too long', 'nome de setor acima de 120 caracteres é recusado (varchar(120))');
SELECT pg_temp.espera_erro($$INSERT INTO usuario (nome, matricula, email, senha_hash, perfil, setor_id) VALUES ('Xavier Lima', '9', 'x@ic.gov.br', '$2b$12$a', 'chefe', '00000000-0000-0000-0000-0000000000a1')$$,
  'usuario_perfil_valores', 'perfil fora da lista é recusado (RF16)');

-- ---------------------------------------------------------------- lotes de lacre
SELECT pg_temp.espera_erro($$SELECT gerar_lote_lacres(10, '00000000-0000-0000-0000-0000000000b2')$$,
  'Só administradores', 'perito não gera lote (RF04)');
SELECT pg_temp.ok(gerar_lote_lacres(10, '00000000-0000-0000-0000-0000000000b1') IS NOT NULL, 'administrador gera lote de 10');
SELECT pg_temp.ok((SELECT count(*) = 10 AND bool_and(situacao = 'disponivel' AND evidencia_id IS NULL) FROM lacre), 'lacres nascem disponíveis e sem evidência (RF04b)');
SELECT pg_temp.ok((SELECT min(numero_lacre) FROM lacre) = 'IC-' || to_char(now(), 'YYYY') || '-000001', 'numeração gerada pelo banco (RNF05)');
SELECT pg_temp.espera_erro($$INSERT INTO lacre (numero_lacre, emissor, lote_id) SELECT 'IC-X', 'instituto', NULL$$,
  'lacre_lote_so_instituto', 'lacre do Instituto sem lote é recusado (RF04d)');
SELECT pg_temp.espera_erro($$DELETE FROM lacre$$, 'permission denied', 'API não apaga lacres');

-- ---------------------------------------------------------------- ocorrência
INSERT INTO ocorrencia (id, codigo_gigante, delegacia_origem, tipo_crime, data_hora_ocorrencia, criado_por_id)
VALUES ('00000000-0000-0000-0000-0000000000c1', 'GIG-2026-004417', '1º DIP', 'homicidio', '2026-11-10 21:00-04', '00000000-0000-0000-0000-0000000000b2');
INSERT INTO ocorrencia_bo (ocorrencia_id, numero_bo, adicionado_por_id)
VALUES ('00000000-0000-0000-0000-0000000000c1', 'BO 2026/118.332', '00000000-0000-0000-0000-0000000000b2');
SELECT pg_temp.espera_erro($$INSERT INTO ocorrencia (codigo_gigante, criado_por_id) VALUES ('gig-2026-004417', '00000000-0000-0000-0000-0000000000b2')$$,
  'ocorrencia_gigante_uk', 'código GIGANTE repetido é recusado (RF02c)');
SELECT pg_temp.espera_erro($$INSERT INTO ocorrencia (criado_por_id) VALUES ('00000000-0000-0000-0000-0000000000b2')$$,
  'ocorrencia_nao_vazia', 'ocorrência vazia é recusada (RF02e)');
SELECT pg_temp.espera_erro($$INSERT INTO ocorrencia (tipo_crime, criado_por_id) VALUES ('estelionato', '00000000-0000-0000-0000-0000000000b2')$$,
  'ocorrencia_tipo_crime_valores', 'tipo de crime fora da lista é recusado');

-- ---------------------------------------------------------------- evidência + coleta
INSERT INTO evidencia (id, codigo, tipo_evidencia, descricao, endereco_coleta, latitude_coleta, longitude_coleta, ocorrencia_id,
                       foto_caminho_arquivo, foto_nome_arquivo, foto_tipo_arquivo, foto_tamanho_bytes, foto_hash_sha256, coletado_por_id)
VALUES ('00000000-0000-0000-0000-0000000000e1', 'EV-2026-0001', 'projetil_municao', 'Projétil deformado',
        'Rua Tapajós, 214, Manaus', -3.130000, -60.023000, '00000000-0000-0000-0000-0000000000c1',
        's3://evidencias/e1.jpg', 'projetil.jpg', 'image/jpeg', 482113, encode(sha256('foto'::bytea), 'hex'),
        '00000000-0000-0000-0000-0000000000b2');

SELECT pg_temp.espera_erro($$INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, endereco_local, cadastro_fora_do_local)
  VALUES ('00000000-0000-0000-0000-0000000000e1', 'coletado', '00000000-0000-0000-0000-0000000000b2', 'Rafael Souza', 'Rua Tapajós, 214', true)$$,
  'cadeia_justificativa', 'cadastro fora do local exige justificativa (RF02b)');

INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, endereco_local, cadastro_fora_do_local,
                             gps_obtido, gps_latitude, gps_longitude, gps_precisao_metros,
                             numero_sequencia, hash_registro_anterior, hash_registro, data_hora_registro)  -- valores falsos: devem ser ignorados
VALUES ('00000000-0000-0000-0000-0000000000e1', 'coletado', '00000000-0000-0000-0000-0000000000b2', 'Rafael Souza',
        'Rua Tapajós, 214, Manaus', false, true, -3.130010, -60.023020, 8.5,
        99, repeat('f', 64), repeat('f', 64), '2000-01-01');
SELECT pg_temp.ok((SELECT numero_sequencia = 1 AND hash_registro_anterior = repeat('0', 64) AND hash_registro <> repeat('f', 64)
                          AND data_hora_registro > now() - interval '1 minute' FROM cadeia_custodia),
                  'sequência, hashes e hora vêm do banco, não do cliente (RNF04, RNF-S1)');

-- Associação do lacre IC-...-000001 (RF05, RF05b)
UPDATE lacre SET situacao = 'vinculado', evidencia_id = '00000000-0000-0000-0000-0000000000e1',
       vinculado_por_id = '00000000-0000-0000-0000-0000000000b2', vinculado_em = now(),
       hash_foto_na_associacao = encode(sha256('foto'::bytea), 'hex')
 WHERE numero_lacre LIKE '%-000001';
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, lacre_id)
SELECT '00000000-0000-0000-0000-0000000000e1', 'lacre_associado', '00000000-0000-0000-0000-0000000000b2', 'Rafael Souza', id
  FROM lacre WHERE numero_lacre LIKE '%-000001';

SELECT pg_temp.espera_erro($$INSERT INTO evidencia (codigo, tipo_evidencia, descricao, endereco_coleta, foto_caminho_arquivo, foto_nome_arquivo, foto_tipo_arquivo, foto_tamanho_bytes, foto_hash_sha256, coletado_por_id) VALUES ('EV-X', 'veiculo', 'x', 'Rua B', 'a', 'a.jpg', 'image/jpeg', 1, repeat('a', 64), '00000000-0000-0000-0000-0000000000b2')$$,
  'evidencia_tipo_evidencia_valores', 'tipo de evidência fora da lista é recusado (RF02)');
SELECT pg_temp.espera_erro($$UPDATE evidencia SET foto_nome_arquivo = 'outra.jpg' WHERE id = '00000000-0000-0000-0000-0000000000e1'$$,
  'não podem ser alterados', 'dados da foto não mudam depois do cadastro (RF03)');
SELECT pg_temp.espera_erro($$INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse) VALUES ('00000000-0000-0000-0000-0000000000e1', 'transferido', '00000000-0000-0000-0000-0000000000b2', 'X')$$,
  'cadeia_acao_valores', 'ação "transferido" não existe (RF13g)');

-- Segunda evidência tenta usar o mesmo lacre (RF05c)
INSERT INTO evidencia (id, codigo, tipo_evidencia, descricao, endereco_coleta, foto_caminho_arquivo, foto_nome_arquivo, foto_tipo_arquivo, foto_tamanho_bytes, foto_hash_sha256, coletado_por_id)
VALUES ('00000000-0000-0000-0000-0000000000e2', 'EV-2026-0002', 'arma_branca', 'Faca', 'Av. Constantino Nery, 1500',
        's3://evidencias/e2.jpg', 'faca.jpg', 'image/jpeg', 100, encode(sha256('faca'::bytea), 'hex'), '00000000-0000-0000-0000-0000000000b2');
SELECT pg_temp.espera_erro($$UPDATE lacre SET evidencia_id = '00000000-0000-0000-0000-0000000000e2' WHERE numero_lacre LIKE '%-000001'$$,
  'já está vinculado', 'lacre vinculado não passa para outra evidência (RF05c)');
SELECT pg_temp.espera_erro($$UPDATE lacre SET situacao = 'vinculado', evidencia_id = '00000000-0000-0000-0000-0000000000e1', vinculado_por_id = '00000000-0000-0000-0000-0000000000b2', vinculado_em = now(), hash_foto_na_associacao = repeat('a', 64) WHERE numero_lacre LIKE '%-000002'$$,
  'lacre_um_ativo_por_evidencia', 'evidência não tem dois lacres ativos');

-- Lacre externo como lacre principal (RF05d) e número repetido (RF05e)
INSERT INTO lacre (numero_lacre, emissor, cadastrado_por_id, situacao, evidencia_id, vinculado_por_id, vinculado_em, hash_foto_na_associacao)
VALUES ('SSP-88231', 'ssp', '00000000-0000-0000-0000-0000000000b2', 'vinculado', '00000000-0000-0000-0000-0000000000e2',
        '00000000-0000-0000-0000-0000000000b2', now(), encode(sha256('faca'::bytea), 'hex'));
SELECT pg_temp.espera_erro($$INSERT INTO lacre (numero_lacre, emissor, cadastrado_por_id) VALUES ('ssp-88231', 'fabricante', '00000000-0000-0000-0000-0000000000b2')$$,
  'lacre_numero_uk', 'número de lacre externo não se repete (RF05e)');

-- Referência a lacre externo ligada ao lacre do Instituto (RF04e)
INSERT INTO lacre_referencia_externa (lacre_id, emissor, numero_lacre_externo, associado_por_id)
SELECT id, 'tribunal_justica', 'TJAM-554', '00000000-0000-0000-0000-0000000000b2' FROM lacre WHERE numero_lacre LIKE '%-000001';
SELECT pg_temp.espera_erro($$INSERT INTO lacre_referencia_externa (lacre_id, emissor, numero_lacre_externo, associado_por_id) SELECT id, 'instituto', 'X', '00000000-0000-0000-0000-0000000000b2' FROM lacre WHERE numero_lacre LIKE '%-000001'$$,
  'check constraint', 'referência externa não pode ser do Instituto');

-- ---------------------------------------------------------------- encaminhamento e recebimento
UPDATE evidencia SET situacao = 'em_transito', setor_destino_pendente_id = '00000000-0000-0000-0000-0000000000a2' WHERE id = '00000000-0000-0000-0000-0000000000e1';
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, setor_destino_id, observacao)
VALUES ('00000000-0000-0000-0000-0000000000e1', 'encaminhado', '00000000-0000-0000-0000-0000000000b2', 'Motorista Pedro (sem login)',
        '00000000-0000-0000-0000-0000000000a2', 'Viatura 12');
SELECT pg_temp.espera_erro($$UPDATE evidencia SET perito_responsavel_id = '00000000-0000-0000-0000-0000000000b4' WHERE id = '00000000-0000-0000-0000-0000000000e1'$$,
  'check constraint', 'em trânsito não tem responsável individual (RF13)');
SELECT pg_temp.espera_erro($$INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse) VALUES ('00000000-0000-0000-0000-0000000000e1', 'encaminhado', '00000000-0000-0000-0000-0000000000b2', 'X')$$,
  'cadeia_encaminhado', 'encaminhamento exige setor ou destino externo (RF08b, RF13b)');

UPDATE evidencia SET situacao = 'recebida', setor_destino_pendente_id = NULL, setor_atual_id = '00000000-0000-0000-0000-0000000000a2' WHERE id = '00000000-0000-0000-0000-0000000000e1';
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, setor_atual_id)
VALUES ('00000000-0000-0000-0000-0000000000e1', 'recebido', '00000000-0000-0000-0000-0000000000b3', 'Júlia Farias', '00000000-0000-0000-0000-0000000000a2');

-- ---------------------------------------------------------------- imutabilidade (RNF03)
SELECT pg_temp.espera_erro($$UPDATE cadeia_custodia SET observacao = 'x'$$, 'permission denied', 'API não altera a cadeia (permissão)');
SELECT pg_temp.espera_erro($$DELETE FROM cadeia_custodia$$, 'permission denied', 'API não apaga a cadeia (permissão)');
RESET ROLE;
SELECT pg_temp.espera_erro($$UPDATE cadeia_custodia SET observacao = 'x'$$, 'apenas inserções', 'nem o dono altera a cadeia (gatilho)');
SELECT pg_temp.espera_erro($$DELETE FROM cadeia_custodia$$, 'apenas inserções', 'nem o dono apaga a cadeia (gatilho)');
SELECT pg_temp.espera_erro($$TRUNCATE cadeia_custodia CASCADE$$, 'apenas inserções', 'nem o dono esvazia a cadeia (gatilho)');
SET ROLE custodia_app;

-- ---------------------------------------------------------------- análise e rompimento (RF07, RF07b)
UPDATE evidencia SET situacao = 'em_analise', perito_responsavel_id = '00000000-0000-0000-0000-0000000000b4' WHERE id = '00000000-0000-0000-0000-0000000000e1';
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, setor_atual_id)
VALUES ('00000000-0000-0000-0000-0000000000e1', 'em_analise', '00000000-0000-0000-0000-0000000000b4', 'Carlos Menezes', '00000000-0000-0000-0000-0000000000a2');

SELECT pg_temp.espera_erro($$UPDATE lacre SET situacao = 'rompido', rompido_por_id = '00000000-0000-0000-0000-0000000000b4', rompido_em = now() WHERE numero_lacre LIKE '%-000001'$$,
  'lacre_rompido', 'rompimento sem motivo é recusado (RF07)');
UPDATE lacre SET situacao = 'rompido', rompido_por_id = '00000000-0000-0000-0000-0000000000b4', rompido_em = now(),
       motivo_rompimento = 'Abertura para exame de microcomparação' WHERE numero_lacre LIKE '%-000001';
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, setor_atual_id, lacre_id, observacao)
SELECT '00000000-0000-0000-0000-0000000000e1', 'lacre_rompido', '00000000-0000-0000-0000-0000000000b4', 'Carlos Menezes',
       '00000000-0000-0000-0000-0000000000a2', id, 'Abertura para exame de microcomparação' FROM lacre WHERE numero_lacre LIKE '%-000001';

SELECT pg_temp.ok((SELECT bloqueada_sem_lacre FROM v_evidencia_situacao WHERE codigo = 'EV-2026-0001'), 'visão marca a evidência bloqueada (RF07b)');
SELECT pg_temp.espera_erro($$INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, setor_atual_id) VALUES ('00000000-0000-0000-0000-0000000000e1', 'analisado', '00000000-0000-0000-0000-0000000000b4', 'Carlos Menezes', '00000000-0000-0000-0000-0000000000a2')$$,
  'sem lacre ativo', 'sem lacre ativo, nenhuma movimentação é aceita (RF07b, RF19b)');
SELECT pg_temp.espera_erro($$UPDATE lacre SET situacao = 'vinculado' WHERE numero_lacre LIKE '%-000001'$$,
  'não pode ser reutilizado', 'lacre rompido não é reutilizado (RF05c)');

UPDATE lacre SET situacao = 'vinculado', evidencia_id = '00000000-0000-0000-0000-0000000000e1',
       vinculado_por_id = '00000000-0000-0000-0000-0000000000b4', vinculado_em = now(),
       hash_foto_na_associacao = encode(sha256('foto'::bytea), 'hex') WHERE numero_lacre LIKE '%-000002';
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, setor_atual_id, lacre_id)
SELECT '00000000-0000-0000-0000-0000000000e1', 'lacre_associado', '00000000-0000-0000-0000-0000000000b4', 'Carlos Menezes',
       '00000000-0000-0000-0000-0000000000a2', id FROM lacre WHERE numero_lacre LIKE '%-000002';
UPDATE evidencia SET situacao = 'analisada', perito_responsavel_id = NULL WHERE id = '00000000-0000-0000-0000-0000000000e1';
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, setor_atual_id, observacao)
VALUES ('00000000-0000-0000-0000-0000000000e1', 'analisado', '00000000-0000-0000-0000-0000000000b4', 'Carlos Menezes',
        '00000000-0000-0000-0000-0000000000a2', 'Laudo em redação');
SELECT pg_temp.ok((SELECT count(*) = 8 FROM cadeia_custodia WHERE evidencia_id = '00000000-0000-0000-0000-0000000000e1'), 'novo lacre libera a evidência e a análise é concluída');

-- ---------------------------------------------------------------- verificação de integridade (RF21, RF22)
SELECT verificar_cadeia('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000b4') AS vid \gset
SELECT pg_temp.ok((SELECT cadeia_integra AND total_registros = 8 FROM verificacao_integridade WHERE id = :'vid'),
                  'cadeia íntegra é reconhecida');

-- Simula adulteração direta no banco por um superusuário que desliga o gatilho.
RESET ROLE;
ALTER TABLE cadeia_custodia DISABLE TRIGGER cadeia_somente_insercao;
UPDATE cadeia_custodia SET nome_responsavel_posse = 'Outra Pessoa' WHERE evidencia_id = '00000000-0000-0000-0000-0000000000e1' AND numero_sequencia = 3;
ALTER TABLE cadeia_custodia ENABLE TRIGGER cadeia_somente_insercao;
SET ROLE custodia_app;

SELECT verificar_cadeia('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000b4') AS vid \gset
SELECT pg_temp.ok((SELECT NOT v.cadeia_integra AND v.registros_divergentes = 1
                          AND d.numero_sequencia = 3 AND d.tipo_divergencia = 'conteudo_alterado'
                          AND d.cadeia_custodia_id IS NOT NULL AND d.hash_armazenado <> d.hash_recalculado
                     FROM verificacao_integridade v JOIN verificacao_divergencia d ON d.verificacao_id = v.id
                    WHERE v.id = :'vid'),
                  'adulteração é apontada no registro exato (RF22)');

-- ---------------------------------------------------------------- devolução encerra (RF13e)
UPDATE evidencia SET situacao = 'devolvida', setor_atual_id = NULL WHERE id = '00000000-0000-0000-0000-0000000000e2';
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, endereco_local, cadastro_fora_do_local)
VALUES ('00000000-0000-0000-0000-0000000000e2', 'coletado', '00000000-0000-0000-0000-0000000000b2', 'Rafael Souza', 'Av. Constantino Nery, 1500', false);
INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, destino_externo_nome, destino_externo_endereco)
VALUES ('00000000-0000-0000-0000-0000000000e2', 'devolvido', '00000000-0000-0000-0000-0000000000b2', 'Rafael Souza', '6º DIP', 'Rua A, 10');
SELECT pg_temp.espera_erro($$INSERT INTO cadeia_custodia (evidencia_id, acao, registrado_por_id, nome_responsavel_posse, setor_destino_id) VALUES ('00000000-0000-0000-0000-0000000000e2', 'armazenado', '00000000-0000-0000-0000-0000000000b2', 'X', '00000000-0000-0000-0000-0000000000a3')$$,
  'cadeia está encerrada', 'nada entra na cadeia depois da devolução (RF13e)');
SELECT pg_temp.espera_erro($$UPDATE evidencia SET situacao = 'armazenada', setor_atual_id = '00000000-0000-0000-0000-0000000000a3' WHERE id = '00000000-0000-0000-0000-0000000000e2'$$,
  'foi devolvida', 'evidência devolvida não muda de situação');

-- ---------------------------------------------------------------- setor em uso não é apagado
SELECT pg_temp.espera_erro($$DELETE FROM setor WHERE id = '00000000-0000-0000-0000-0000000000a2'$$,
  'foreign key', 'setor em uso não é apagado (só desativado)');

RESET ROLE;
SELECT 'Todos os testes passaram.';
