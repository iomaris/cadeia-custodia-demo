-- =============================================================================
-- Cadeia de Custódia de Evidências (MVP) - esquema do banco de dados
-- PostgreSQL 14 ou superior (testado no 16). Nenhuma extensão é necessária.
--
-- Como aplicar (banco vazio):
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f schema.sql
--
-- Organização do arquivo:
--   1. Esquema e tipos enumerados
--   2. Tabelas
--   3. Funções de apoio e gatilhos (imutabilidade, hash chain, regras de lacre)
--   4. Funções de negócio (gerar lote de lacres, verificar integridade)
--   5. Visões
--   6. Índices
--   7. Papéis e permissões
-- =============================================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS custodia;
SET search_path = custodia, public;

-- =============================================================================
-- 1. TIPOS ENUMERADOS (listas fixas do MVP; não há CRUD de tipos - fora do escopo)
-- =============================================================================

-- RF16: três perfis de acesso.
CREATE TYPE papel_usuario AS ENUM ('perito', 'normal', 'administrador');

-- RF02: tipo de evidência (lista fixa).
CREATE TYPE tipo_evidencia AS ENUM (
  'arma_de_fogo', 'projetil_municao', 'arma_branca', 'dispositivo_eletronico',
  'documento', 'material_biologico', 'substancia_entorpecente',
  'vestigio_papiloscopico', 'outro'
);

-- RF02b (pop-up de ocorrência): tipo de crime (lista fixa).
CREATE TYPE tipo_crime AS ENUM (
  'homicidio', 'roubo', 'furto', 'trafico_drogas', 'lesao_corporal',
  'crime_cibernetico', 'outro'
);

-- Situação atual da evidência (cópia de leitura rápida; a fonte da verdade é a cadeia).
CREATE TYPE status_evidencia AS ENUM (
  'coletada',            -- criada no cadastro (RF08c)
  'em_transito',         -- encaminhada, aguardando recebimento (RF12, RF12c)
  'recebida',            -- recebida em um setor do Instituto (RF14)
  'em_analise',          -- análise assumida por um perito (RF18)
  'analisada',           -- análise concluída (RF19)
  'armazenada',          -- guardada em um setor (RF08b)
  'em_destino_externo',  -- chegou a um destino fora do Instituto (RF13c)
  'devolvida'            -- posse do Instituto encerrada (RF13e); estado final
);

-- RF04b, RF05b, RF07.
CREATE TYPE status_lacre AS ENUM ('disponivel', 'vinculado', 'rompido');

-- RF04d, RF04e, RF05d, RF06b: quem emitiu o lacre.
CREATE TYPE emissor_lacre AS ENUM (
  'instituto',         -- lacres gerados em lote pelo próprio Instituto (único emissor com lote)
  'ssp', 'senasp_mj', 'tribunal_justica', 'policia_federal',
  'pericia_externa', 'fabricante', 'outro'
);

-- Ações registradas na cadeia de custódia.
-- Amplia a lista do documento (5 valores) para cobrir RF13e, RF18 e os eventos de lacre.
-- "transferido" foi removido pelo RF13g e não existe aqui.
CREATE TYPE acao_custodia AS ENUM (
  'coletado',                 -- criado automaticamente no cadastro (RF08c)
  'encaminhado',              -- para setor interno ou destino externo (RF12, RF13b)
  'recebido',                 -- recebimento confirmado no setor de destino (RF14)
  'chegada_destino_externo',  -- chegada confirmada fora do Instituto (RF13c)
  'em_analise',               -- perito assumiu a análise (RF17, RF18)
  'analisado',                -- perito concluiu a análise (RF19)
  'armazenado',               -- guardado em um setor (RF08b)
  'devolvido',                -- posse encerrada (RF13e)
  'lacre_associado',          -- lacre afixado e vinculado (RF05, RF05b)
  'lacre_rompido'             -- lacre rompido, com motivo (RF07)
);

-- Resultado de cada registro em uma verificação de integridade (RF21, RF22).
CREATE TYPE tipo_divergencia AS ENUM (
  'conteudo_alterado',  -- o hash recalculado não bate com o hash guardado
  'elo_quebrado',       -- hash_anterior não é o hash do registro anterior
  'sequencia_quebrada'  -- falta um número de sequência (registro apagado)
);

-- Ações auditadas no log de acesso (RNF sugerido S7, LGPD).
CREATE TYPE acao_acesso AS ENUM (
  'visualizou_evidencia', 'visualizou_cadeia', 'exportou_pdf', 'exportou_csv', 'verificou_integridade'
);

-- =============================================================================
-- 2. TABELAS
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 2.1 setor (RF10, RF11): setores do Instituto. Nunca é apagado se estiver em uso;
--     desative com ativo = false.
-- -----------------------------------------------------------------------------
CREATE TABLE setor (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  nome           text        NOT NULL CHECK (length(btrim(nome)) BETWEEN 2 AND 120),
  ativo          boolean     NOT NULL DEFAULT true,
  criado_em      timestamptz NOT NULL DEFAULT now(),
  atualizado_em  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX setor_nome_uk ON setor (lower(btrim(nome)));
COMMENT ON TABLE setor IS 'Setores do Instituto (Recepção, Laboratório de Balística, Depósito...). RF10, RF11.';

-- -----------------------------------------------------------------------------
-- 2.2 usuario (RF01, RF11, RF16)
-- -----------------------------------------------------------------------------
CREATE TABLE usuario (
  id             uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  nome           text          NOT NULL CHECK (length(btrim(nome)) BETWEEN 2 AND 160),
  matricula      text          NOT NULL CHECK (length(btrim(matricula)) BETWEEN 1 AND 30),
  email          text          NOT NULL CHECK (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  senha_hash     text          NOT NULL CHECK (senha_hash ~ '^\$(2[aby]|argon2id)\$'),
  papel          papel_usuario NOT NULL DEFAULT 'normal',
  setor_id       uuid          NOT NULL REFERENCES setor (id) ON DELETE RESTRICT,
  ativo          boolean       NOT NULL DEFAULT true,
  ultimo_login_em timestamptz,
  criado_em      timestamptz   NOT NULL DEFAULT now(),
  atualizado_em  timestamptz   NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX usuario_matricula_uk ON usuario (lower(btrim(matricula)));
CREATE UNIQUE INDEX usuario_email_uk     ON usuario (lower(btrim(email)));
COMMENT ON COLUMN usuario.senha_hash IS 'Hash bcrypt ($2a/$2b/$2y) ou Argon2id. Nunca a senha.';
COMMENT ON COLUMN usuario.ativo IS 'Usuários que aparecem em cadeias não podem ser apagados; desative.';

-- -----------------------------------------------------------------------------
-- 2.3 token_revogado (RF01 logout): JWT é sem estado; para o logout valer antes
--     de o token expirar, o identificador (jti) entra nesta lista até expirar.
-- -----------------------------------------------------------------------------
CREATE TABLE token_revogado (
  jti         uuid        PRIMARY KEY,
  usuario_id  uuid        NOT NULL REFERENCES usuario (id) ON DELETE CASCADE,
  expira_em   timestamptz NOT NULL,
  revogado_em timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE token_revogado IS 'Tokens JWT invalidados por logout. Linhas com expira_em no passado podem ser apagadas por rotina diária.';

-- -----------------------------------------------------------------------------
-- 2.4 ocorrencia + ocorrencia_bo (RF02b pop-up, RF02c, RF02d, RF02e)
-- -----------------------------------------------------------------------------
CREATE TABLE ocorrencia (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  codigo_gigante_ssp  text        CHECK (codigo_gigante_ssp IS NULL OR length(btrim(codigo_gigante_ssp)) > 0),
  numero_oficio       text,
  delegacia_origem    text,
  tipo_crime          tipo_crime,
  data_hora           timestamptz,               -- quando a ocorrência aconteceu (opcional)
  endereco            text,
  observacoes         text,
  criada_por          uuid        NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  criada_em           timestamptz NOT NULL DEFAULT now(),
  atualizado_em       timestamptz NOT NULL DEFAULT now(),
  -- RF02e: uma ocorrência só é criada se tiver ao menos um dado preenchido.
  CONSTRAINT ocorrencia_nao_vazia CHECK (
    codigo_gigante_ssp IS NOT NULL OR numero_oficio IS NOT NULL OR delegacia_origem IS NOT NULL
    OR tipo_crime IS NOT NULL OR data_hora IS NOT NULL OR endereco IS NOT NULL OR observacoes IS NOT NULL
  )
);
-- RF02c/RF02d: o código GIGANTE identifica a ocorrência (busca sem diferenciar maiúsculas).
CREATE UNIQUE INDEX ocorrencia_gigante_uk ON ocorrencia (upper(btrim(codigo_gigante_ssp)))
  WHERE codigo_gigante_ssp IS NOT NULL;

CREATE TABLE ocorrencia_bo (
  ocorrencia_id  uuid        NOT NULL REFERENCES ocorrencia (id) ON DELETE CASCADE,
  numero_bo      text        NOT NULL CHECK (length(btrim(numero_bo)) > 0),
  adicionado_por uuid        NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  adicionado_em  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ocorrencia_id, numero_bo)
);
COMMENT ON TABLE ocorrencia_bo IS 'B.O.s de uma ocorrência (1:N). A evidência herda o vínculo via evidencia.ocorrencia_id.';

-- -----------------------------------------------------------------------------
-- 2.5 evidencia (RF02, RF03, RF12, RF13, RF17-RF19)
--     Os campos de situação (status, setor_atual_id...) são uma cópia de leitura
--     rápida, atualizada pela API na mesma transação que grava a cadeia.
-- -----------------------------------------------------------------------------
CREATE TABLE evidencia (
  id                        uuid             PRIMARY KEY DEFAULT gen_random_uuid(),
  codigo                    text             NOT NULL CHECK (length(btrim(codigo)) BETWEEN 1 AND 40),
  tipo                      tipo_evidencia   NOT NULL,
  descricao                 text             NOT NULL CHECK (length(btrim(descricao)) > 0),
  -- Local onde foi encontrada (RF02: endereço + localização geográfica)
  endereco_encontrada       text             NOT NULL,
  latitude_encontrada       numeric(9,6)     CHECK (latitude_encontrada BETWEEN -90 AND 90),
  longitude_encontrada      numeric(9,6)     CHECK (longitude_encontrada BETWEEN -180 AND 180),
  ocorrencia_id             uuid             REFERENCES ocorrencia (id) ON DELETE RESTRICT,  -- opcional (RF02e)
  -- Foto e integridade do arquivo (RF02, RF03)
  foto_url                  text             NOT NULL,
  foto_nome_original        text             NOT NULL,
  foto_mime                 text             NOT NULL CHECK (foto_mime IN ('image/jpeg', 'image/png', 'image/heic', 'image/webp')),
  foto_tamanho_bytes        bigint           NOT NULL CHECK (foto_tamanho_bytes > 0),
  foto_hash_sha256          char(64)         NOT NULL CHECK (foto_hash_sha256 ~ '^[0-9a-f]{64}$'),
  -- Coleta
  coletado_por              uuid             NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  coletado_em               timestamptz      NOT NULL DEFAULT now(),
  -- Situação atual (cópia de leitura rápida da cadeia)
  status                    status_evidencia NOT NULL DEFAULT 'coletada',
  setor_atual_id            uuid             REFERENCES setor (id) ON DELETE RESTRICT,
  setor_pendente_id         uuid             REFERENCES setor (id) ON DELETE RESTRICT,  -- destino interno em trânsito
  destino_externo_nome      text,                                                       -- destino externo (RF13b)
  destino_externo_endereco  text,
  perito_analisando_id      uuid             REFERENCES usuario (id) ON DELETE RESTRICT,
  criado_em                 timestamptz      NOT NULL DEFAULT now(),
  atualizado_em             timestamptz      NOT NULL DEFAULT now(),

  CONSTRAINT evidencia_coordenadas_juntas CHECK ((latitude_encontrada IS NULL) = (longitude_encontrada IS NULL)),
  CONSTRAINT evidencia_destino_externo_completo CHECK ((destino_externo_nome IS NULL) = (destino_externo_endereco IS NULL)),
  -- RF13: em trânsito não há setor atual nem responsável individual, só o destino.
  CONSTRAINT evidencia_em_transito CHECK (
    status <> 'em_transito'
    OR (setor_atual_id IS NULL AND perito_analisando_id IS NULL
        AND ((setor_pendente_id IS NOT NULL) <> (destino_externo_nome IS NOT NULL)))
  ),
  CONSTRAINT evidencia_pendente_so_em_transito CHECK (setor_pendente_id IS NULL OR status = 'em_transito'),
  -- RF17/RF18: em análise exige setor e perito; fora dela, nenhum perito.
  CONSTRAINT evidencia_em_analise CHECK (
    (status = 'em_analise' AND perito_analisando_id IS NOT NULL AND setor_atual_id IS NOT NULL)
    OR (status <> 'em_analise' AND perito_analisando_id IS NULL)
  ),
  CONSTRAINT evidencia_no_setor CHECK (status NOT IN ('recebida', 'analisada', 'armazenada') OR setor_atual_id IS NOT NULL),
  CONSTRAINT evidencia_destino_externo CHECK (status <> 'em_destino_externo' OR destino_externo_nome IS NOT NULL),
  CONSTRAINT evidencia_devolvida CHECK (status <> 'devolvida' OR (setor_atual_id IS NULL AND setor_pendente_id IS NULL))
);
CREATE UNIQUE INDEX evidencia_codigo_uk ON evidencia (upper(btrim(codigo)));
COMMENT ON COLUMN evidencia.foto_hash_sha256 IS 'SHA-256 do arquivo da foto, calculado no backend no upload (RF03, RNF04).';
COMMENT ON COLUMN evidencia.status IS 'Cópia de leitura rápida. A cadeia_custodia é a fonte da verdade.';

-- -----------------------------------------------------------------------------
-- 2.6 lote_lacre (RF04, RF06): lotes impressos com antecedência pelo Instituto.
-- -----------------------------------------------------------------------------
CREATE SEQUENCE lote_lacre_seq;
CREATE SEQUENCE lacre_numero_seq;

CREATE TABLE lote_lacre (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  codigo          text        NOT NULL UNIQUE,                     -- ex.: L-2026-0001
  quantidade      integer     NOT NULL CHECK (quantidade BETWEEN 1 AND 500),
  primeiro_numero text        NOT NULL,
  ultimo_numero   text        NOT NULL,
  gerado_por      uuid        NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  gerado_em       timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 2.7 lacre (RF04-RF07c): lacre de cada evidência. Inclui os lacres do Instituto
--     (com lote e QR code) e os lacres externos usados como lacre principal
--     (RF05d: fabricante, SENASP/MJ, SSP...), que não têm lote.
--     O QR code codifica só numero (RF04c); por isso não há coluna qr_payload.
-- -----------------------------------------------------------------------------
CREATE TABLE lacre (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  numero                      text          NOT NULL CHECK (length(btrim(numero)) BETWEEN 1 AND 60),
  emissor                     emissor_lacre NOT NULL,
  lote_id                     uuid          REFERENCES lote_lacre (id) ON DELETE RESTRICT,
  status                      status_lacre  NOT NULL DEFAULT 'disponivel',
  evidencia_id                uuid          REFERENCES evidencia (id) ON DELETE RESTRICT,
  hash_no_momento_associacao  char(64)      CHECK (hash_no_momento_associacao ~ '^[0-9a-f]{64}$'),
  registrado_por              uuid          REFERENCES usuario (id) ON DELETE RESTRICT,  -- quem cadastrou um lacre externo
  registrado_em               timestamptz   NOT NULL DEFAULT now(),
  vinculado_por               uuid          REFERENCES usuario (id) ON DELETE RESTRICT,
  vinculado_em                timestamptz,
  rompido_por                 uuid          REFERENCES usuario (id) ON DELETE RESTRICT,
  motivo_rompimento           text,
  rompido_em                  timestamptz,

  -- RF04d: só o Instituto tem lote; lacre externo nunca tem lote.
  CONSTRAINT lacre_lote_so_instituto CHECK ((emissor = 'instituto') = (lote_id IS NOT NULL)),
  CONSTRAINT lacre_externo_tem_autor CHECK (emissor = 'instituto' OR registrado_por IS NOT NULL),
  -- RF04b: disponível = sem evidência e sem dados de vínculo.
  CONSTRAINT lacre_disponivel CHECK (
    status <> 'disponivel'
    OR (evidencia_id IS NULL AND vinculado_por IS NULL AND vinculado_em IS NULL AND rompido_por IS NULL)
  ),
  -- RF05b: vinculado guarda evidência, autor, data e o hash da evidência no momento.
  CONSTRAINT lacre_vinculado CHECK (
    status = 'disponivel'
    OR (evidencia_id IS NOT NULL AND vinculado_por IS NOT NULL AND vinculado_em IS NOT NULL
        AND hash_no_momento_associacao IS NOT NULL)
  ),
  -- RF07: rompimento exige responsável, motivo e data.
  CONSTRAINT lacre_rompido CHECK (
    (status = 'rompido') = (rompido_por IS NOT NULL AND rompido_em IS NOT NULL
                             AND motivo_rompimento IS NOT NULL AND length(btrim(motivo_rompimento)) > 0)
  )
);
-- RNF05, RF05e: número único no sistema inteiro, inclusive externos e histórico.
CREATE UNIQUE INDEX lacre_numero_uk ON lacre (upper(btrim(numero)));
-- RF05c/RF07b: no máximo um lacre ativo por evidência.
CREATE UNIQUE INDEX lacre_um_ativo_por_evidencia ON lacre (evidencia_id) WHERE status = 'vinculado';
COMMENT ON COLUMN lacre.numero IS 'Número impresso no lacre. Para lacres do Instituto, gerado pelo banco (RNF05) e é o único conteúdo do QR code (RF04c).';

-- -----------------------------------------------------------------------------
-- 2.8 lacre_referencia_externa (RF04e): lacres de outras instituições que já
--     estavam na evidência, ligados ao lacre do Instituto como registro histórico.
--     Corresponde à entidade "LacreExterno" do documento.
-- -----------------------------------------------------------------------------
CREATE TABLE lacre_referencia_externa (
  id              uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  lacre_id        uuid          NOT NULL REFERENCES lacre (id) ON DELETE RESTRICT,
  emissor         emissor_lacre NOT NULL CHECK (emissor <> 'instituto'),
  numero_externo  text          NOT NULL CHECK (length(btrim(numero_externo)) > 0),
  observacao      text,
  associado_por   uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  associado_em    timestamptz   NOT NULL DEFAULT now(),
  UNIQUE (lacre_id, emissor, numero_externo)
);

-- -----------------------------------------------------------------------------
-- 2.9 cadeia_custodia (RF08-RF09, RF12-RF20, RNF03, RNF04)
--     Log somente de inserção. sequencia, hash_anterior, data_hora e hash_registro
--     são preenchidos pelo gatilho; valores enviados pela aplicação são ignorados.
-- -----------------------------------------------------------------------------
CREATE TABLE cadeia_custodia (
  id                        uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  evidencia_id              uuid          NOT NULL REFERENCES evidencia (id) ON DELETE RESTRICT,
  sequencia                 integer       NOT NULL CHECK (sequencia >= 1),
  acao                      acao_custodia NOT NULL,
  registrado_por            uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT, -- usuário logado
  responsavel_nome          text          NOT NULL CHECK (length(btrim(responsavel_nome)) > 0), -- quem tem a posse física (ex.: transportador sem login)
  setor_id                  uuid          REFERENCES setor (id) ON DELETE RESTRICT,   -- onde a ação aconteceu
  setor_destino_id          uuid          REFERENCES setor (id) ON DELETE RESTRICT,   -- encaminhado/armazenado (RF08b)
  destino_externo_nome      text,                                                     -- RF13b
  destino_externo_endereco  text,
  local                     text,                                                     -- endereço livre (coleta, destino externo)
  lacre_id                  uuid          REFERENCES lacre (id) ON DELETE RESTRICT,   -- eventos de lacre
  data_hora                 timestamptz   NOT NULL DEFAULT now(),                     -- hora do servidor
  observacao                text,
  -- Localização real do dispositivo (RF02b, RF13c, RF13f)
  localizacao_obtida        boolean       NOT NULL DEFAULT false,
  latitude                  numeric(9,6)  CHECK (latitude BETWEEN -90 AND 90),
  longitude                 numeric(9,6)  CHECK (longitude BETWEEN -180 AND 180),
  precisao_m                numeric(8,1)  CHECK (precisao_m >= 0),
  -- Cadastro fora do local indicado (RF02b), só na ação "coletado"
  fora_do_local             boolean,
  justificativa_fora_local  text,
  -- Hash chain (RF09)
  hash_anterior             char(64)      NOT NULL CHECK (hash_anterior ~ '^[0-9a-f]{64}$'),
  hash_registro             char(64)      NOT NULL CHECK (hash_registro ~ '^[0-9a-f]{64}$'),

  UNIQUE (evidencia_id, sequencia),
  UNIQUE (evidencia_id, hash_anterior),   -- impede duas ramificações a partir do mesmo registro
  UNIQUE (hash_registro),
  CONSTRAINT cadeia_genese CHECK ((sequencia = 1) = (hash_anterior = repeat('0', 64))),
  CONSTRAINT cadeia_coordenadas CHECK (
    (localizacao_obtida AND latitude IS NOT NULL AND longitude IS NOT NULL)
    OR (NOT localizacao_obtida AND latitude IS NULL AND longitude IS NULL AND precisao_m IS NULL)
  ),
  CONSTRAINT cadeia_destino_externo_completo CHECK ((destino_externo_nome IS NULL) = (destino_externo_endereco IS NULL)),
  -- Regras por ação
  CONSTRAINT cadeia_coletado CHECK (
    acao <> 'coletado' OR (sequencia = 1 AND local IS NOT NULL AND fora_do_local IS NOT NULL)
  ),
  CONSTRAINT cadeia_so_coleta_e_primeira CHECK (sequencia <> 1 OR acao = 'coletado'),
  CONSTRAINT cadeia_justificativa CHECK (
    (fora_do_local IS NULL AND justificativa_fora_local IS NULL)
    OR (fora_do_local = false AND justificativa_fora_local IS NULL)
    OR (fora_do_local = true AND length(btrim(coalesce(justificativa_fora_local, ''))) > 0)
  ),
  CONSTRAINT cadeia_fora_do_local_so_na_coleta CHECK (acao = 'coletado' OR fora_do_local IS NULL),
  CONSTRAINT cadeia_encaminhado CHECK (
    acao <> 'encaminhado' OR ((setor_destino_id IS NOT NULL) <> (destino_externo_nome IS NOT NULL))
  ),
  CONSTRAINT cadeia_armazenado CHECK (acao <> 'armazenado' OR setor_destino_id IS NOT NULL),
  CONSTRAINT cadeia_recebido CHECK (acao NOT IN ('recebido', 'em_analise', 'analisado') OR setor_id IS NOT NULL),
  CONSTRAINT cadeia_chegada_externa CHECK (acao <> 'chegada_destino_externo' OR local IS NOT NULL),
  CONSTRAINT cadeia_devolvido CHECK (acao <> 'devolvido' OR local IS NOT NULL OR destino_externo_nome IS NOT NULL),
  CONSTRAINT cadeia_evento_lacre CHECK ((acao IN ('lacre_associado', 'lacre_rompido')) = (lacre_id IS NOT NULL))
);
COMMENT ON TABLE cadeia_custodia IS 'Log somente de inserção (RNF03). Cada registro é encadeado ao anterior por SHA-256 (RF09).';
COMMENT ON COLUMN cadeia_custodia.responsavel_nome IS 'Nome de quem tem a posse física, gravado como texto para que o hash não dependa de alterações na tabela usuario.';

-- -----------------------------------------------------------------------------
-- 2.10 verificacao_integridade + verificacao_divergencia (RF21-RF23)
-- -----------------------------------------------------------------------------
CREATE TABLE verificacao_integridade (
  id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  evidencia_id          uuid        NOT NULL REFERENCES evidencia (id) ON DELETE RESTRICT,
  executada_por         uuid        NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  executada_em          timestamptz NOT NULL DEFAULT now(),
  total_registros       integer     NOT NULL CHECK (total_registros >= 0),
  registros_divergentes integer     NOT NULL CHECK (registros_divergentes >= 0),
  integra               boolean     GENERATED ALWAYS AS (registros_divergentes = 0) STORED,
  hash_ultimo_registro  char(64)    -- hash do último registro no momento da verificação
);

CREATE TABLE verificacao_divergencia (
  verificacao_id    uuid             NOT NULL REFERENCES verificacao_integridade (id) ON DELETE RESTRICT,
  sequencia         integer          NOT NULL,
  cadeia_id         uuid             REFERENCES cadeia_custodia (id) ON DELETE RESTRICT,
  tipo              tipo_divergencia NOT NULL,
  hash_armazenado   char(64),
  hash_recalculado  char(64),
  PRIMARY KEY (verificacao_id, sequencia, tipo)
);
COMMENT ON TABLE verificacao_divergencia IS 'Um registro por movimentação que não conferiu (RF22).';

-- -----------------------------------------------------------------------------
-- 2.11 log_acesso (RNF sugerido S7): quem consultou ou exportou cada evidência.
-- -----------------------------------------------------------------------------
CREATE TABLE log_acesso (
  id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  usuario_id    uuid        NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  evidencia_id  uuid        REFERENCES evidencia (id) ON DELETE RESTRICT,
  acao          acao_acesso NOT NULL,
  ip            inet,
  user_agent    text,
  ocorrido_em   timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- 3. FUNÇÕES DE APOIO E GATILHOS
-- =============================================================================

-- 3.1 atualizado_em automático
CREATE FUNCTION tg_atualizado_em() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.atualizado_em := now();
  RETURN NEW;
END $$;

CREATE TRIGGER setor_atualizado_em      BEFORE UPDATE ON setor      FOR EACH ROW EXECUTE FUNCTION tg_atualizado_em();
CREATE TRIGGER usuario_atualizado_em    BEFORE UPDATE ON usuario    FOR EACH ROW EXECUTE FUNCTION tg_atualizado_em();
CREATE TRIGGER ocorrencia_atualizado_em BEFORE UPDATE ON ocorrencia FOR EACH ROW EXECUTE FUNCTION tg_atualizado_em();
CREATE TRIGGER evidencia_atualizado_em  BEFORE UPDATE ON evidencia  FOR EACH ROW EXECUTE FUNCTION tg_atualizado_em();

-- 3.2 Tabelas somente de inserção (RNF03): bloqueia UPDATE e DELETE para qualquer
--     usuário, inclusive o dono das tabelas. Só um superusuário que desligue o
--     gatilho consegue alterar - e a verificação de integridade detecta.
CREATE FUNCTION tg_somente_insercao() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'A tabela % aceita apenas inserções: registros não podem ser alterados nem apagados.', TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER cadeia_somente_insercao        BEFORE UPDATE OR DELETE ON cadeia_custodia          FOR EACH ROW EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER cadeia_sem_truncate            BEFORE TRUNCATE ON cadeia_custodia                   FOR EACH STATEMENT EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER verificacao_somente_insercao   BEFORE UPDATE OR DELETE ON verificacao_integridade  FOR EACH ROW EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER divergencia_somente_insercao   BEFORE UPDATE OR DELETE ON verificacao_divergencia  FOR EACH ROW EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER ref_externa_somente_insercao   BEFORE UPDATE OR DELETE ON lacre_referencia_externa FOR EACH ROW EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER log_acesso_somente_insercao    BEFORE UPDATE OR DELETE ON log_acesso               FOR EACH ROW EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER lote_somente_insercao          BEFORE UPDATE OR DELETE ON lote_lacre               FOR EACH ROW EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER verificacao_sem_truncate      BEFORE TRUNCATE ON verificacao_integridade          FOR EACH STATEMENT EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER divergencia_sem_truncate      BEFORE TRUNCATE ON verificacao_divergencia          FOR EACH STATEMENT EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER ref_externa_sem_truncate      BEFORE TRUNCATE ON lacre_referencia_externa         FOR EACH STATEMENT EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER log_acesso_sem_truncate       BEFORE TRUNCATE ON log_acesso                       FOR EACH STATEMENT EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER lote_sem_truncate             BEFORE TRUNCATE ON lote_lacre                       FOR EACH STATEMENT EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER lacre_sem_truncate            BEFORE TRUNCATE ON lacre                            FOR EACH STATEMENT EXECUTE FUNCTION tg_somente_insercao();
CREATE TRIGGER evidencia_sem_truncate        BEFORE TRUNCATE ON evidencia                        FOR EACH STATEMENT EXECUTE FUNCTION tg_somente_insercao();

-- 3.3 Formato canônico do registro para o hash (RF09, RNF04).
--     Qualquer mudança nesta função invalida as verificações dos registros antigos.
--     Formato: hash_anterior || '|' || texto JSON do array abaixo, nesta ordem.
CREATE FUNCTION cadeia_conteudo_canonico(r cadeia_custodia) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT r.hash_anterior || '|' || json_build_array(
    'v1',                                    -- versão do formato
    r.id, r.evidencia_id, r.sequencia, r.acao, r.registrado_por, r.responsavel_nome,
    r.setor_id, r.setor_destino_id, r.destino_externo_nome, r.destino_externo_endereco,
    r.local, r.lacre_id,
    to_char(r.data_hora AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    r.observacao, r.localizacao_obtida, r.latitude::text, r.longitude::text, r.precisao_m::text,
    r.fora_do_local, r.justificativa_fora_local
  )::text
$$;

CREATE FUNCTION cadeia_calcular_hash(r cadeia_custodia) RETURNS char(64)
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(cadeia_conteudo_canonico(r), 'UTF8')), 'hex')
$$;

-- 3.4 Inserção na cadeia: trava a evidência (serializa movimentações simultâneas),
--     define sequência, hash anterior, hora do servidor e hash; aplica o bloqueio
--     por lacre rompido (RF07b) e o encerramento por devolução (RF13e).
CREATE FUNCTION tg_cadeia_antes_inserir() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_ultimo      cadeia_custodia%ROWTYPE;
  v_status      status_evidencia;
  v_teve_lacre  boolean;
  v_lacre_ativo boolean;
BEGIN
  -- Trava a linha da evidência até o fim da transação.
  SELECT status INTO v_status FROM evidencia WHERE id = NEW.evidencia_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Evidência % não existe.', NEW.evidencia_id USING ERRCODE = 'foreign_key_violation';
  END IF;

  SELECT * INTO v_ultimo FROM cadeia_custodia
   WHERE evidencia_id = NEW.evidencia_id ORDER BY sequencia DESC LIMIT 1;

  IF FOUND THEN
    IF v_ultimo.acao = 'devolvido' THEN
      RAISE EXCEPTION 'A evidência foi devolvida; a cadeia está encerrada (RF13e).' USING ERRCODE = 'check_violation';
    END IF;
    NEW.sequencia     := v_ultimo.sequencia + 1;
    NEW.hash_anterior := v_ultimo.hash_registro;
  ELSE
    NEW.sequencia     := 1;
    NEW.hash_anterior := repeat('0', 64);
  END IF;

  -- RF07b: lacre rompido sem substituto bloqueia tudo, exceto eventos de lacre.
  IF NEW.acao NOT IN ('lacre_associado', 'lacre_rompido') THEN
    SELECT EXISTS (SELECT 1 FROM lacre WHERE evidencia_id = NEW.evidencia_id),
           EXISTS (SELECT 1 FROM lacre WHERE evidencia_id = NEW.evidencia_id AND status = 'vinculado')
      INTO v_teve_lacre, v_lacre_ativo;
    IF v_teve_lacre AND NOT v_lacre_ativo THEN
      RAISE EXCEPTION 'Evidência sem lacre ativo: associe um novo lacre antes de qualquer movimentação (RF07b).'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  NEW.data_hora     := now();                 -- hora do servidor, nunca do dispositivo
  NEW.hash_registro := cadeia_calcular_hash(NEW);
  RETURN NEW;
END $$;

CREATE TRIGGER cadeia_antes_inserir BEFORE INSERT ON cadeia_custodia
  FOR EACH ROW EXECUTE FUNCTION tg_cadeia_antes_inserir();

-- 3.5 Ciclo de vida do lacre (RF04b, RF05b, RF05c, RF07):
--     disponivel -> vinculado -> rompido. Rompido é final. Número, emissor e lote
--     nunca mudam; a evidência só é definida uma vez.
CREATE FUNCTION tg_lacre_ciclo_de_vida() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Lacres não podem ser apagados.' USING ERRCODE = 'insufficient_privilege';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.emissor = 'instituto' AND NEW.status <> 'disponivel' THEN
      RAISE EXCEPTION 'Lacre do Instituto nasce disponível (RF04b).' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'rompido' THEN
      RAISE EXCEPTION 'Um lacre não pode ser cadastrado já rompido.' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.numero IS DISTINCT FROM OLD.numero OR NEW.emissor IS DISTINCT FROM OLD.emissor
     OR NEW.lote_id IS DISTINCT FROM OLD.lote_id OR NEW.registrado_em IS DISTINCT FROM OLD.registrado_em THEN
    RAISE EXCEPTION 'Número, emissor e lote do lacre não podem ser alterados.' USING ERRCODE = 'check_violation';
  END IF;

  IF OLD.status = 'rompido' THEN
    RAISE EXCEPTION 'O lacre % foi rompido e não pode ser reutilizado (RF05c).', OLD.numero USING ERRCODE = 'check_violation';
  END IF;

  IF OLD.status = 'vinculado' THEN
    IF NEW.status = 'disponivel' THEN
      RAISE EXCEPTION 'Um lacre vinculado não volta a ficar disponível.' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.evidencia_id IS DISTINCT FROM OLD.evidencia_id
       OR NEW.vinculado_por IS DISTINCT FROM OLD.vinculado_por
       OR NEW.vinculado_em IS DISTINCT FROM OLD.vinculado_em
       OR NEW.hash_no_momento_associacao IS DISTINCT FROM OLD.hash_no_momento_associacao THEN
      RAISE EXCEPTION 'O lacre % já está vinculado à outra evidência (RF05c).', OLD.numero USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  RETURN NEW;
END $$;

CREATE TRIGGER lacre_ciclo_de_vida BEFORE INSERT OR UPDATE OR DELETE ON lacre
  FOR EACH ROW EXECUTE FUNCTION tg_lacre_ciclo_de_vida();

-- 3.6 Evidência devolvida é estado final (RF13e); evidências e ocorrências não são apagadas.
CREATE FUNCTION tg_evidencia_protecao() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Evidências não podem ser apagadas.' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.status = 'devolvida' THEN
    RAISE EXCEPTION 'A evidência % foi devolvida e não pode mais ser alterada.', OLD.codigo USING ERRCODE = 'check_violation';
  END IF;
  -- Dados de identificação e da foto não mudam depois do cadastro.
  IF NEW.codigo IS DISTINCT FROM OLD.codigo OR NEW.foto_hash_sha256 IS DISTINCT FROM OLD.foto_hash_sha256
     OR NEW.foto_url IS DISTINCT FROM OLD.foto_url OR NEW.coletado_por IS DISTINCT FROM OLD.coletado_por
     OR NEW.coletado_em IS DISTINCT FROM OLD.coletado_em THEN
    RAISE EXCEPTION 'Código, foto e dados de coleta da evidência não podem ser alterados.' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER evidencia_protecao BEFORE UPDATE OR DELETE ON evidencia
  FOR EACH ROW EXECUTE FUNCTION tg_evidencia_protecao();

-- =============================================================================
-- 4. FUNÇÕES DE NEGÓCIO
-- =============================================================================

-- 4.1 Gera um lote de lacres do Instituto (RF04, RNF05). Só administradores.
--     Números no formato IC-<ano>-<6 dígitos>, sequenciais e únicos.
CREATE FUNCTION gerar_lote_lacres(p_quantidade integer, p_usuario uuid) RETURNS uuid
LANGUAGE plpgsql AS $$
DECLARE
  v_lote   uuid;
  v_codigo text;
  v_ano    text := to_char(now(), 'YYYY');
  v_numeros text[];
BEGIN
  IF NOT EXISTS (SELECT 1 FROM usuario WHERE id = p_usuario AND papel = 'administrador' AND ativo) THEN
    RAISE EXCEPTION 'Só administradores geram lotes de lacres (RF04).' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_quantidade IS NULL OR p_quantidade NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'Quantidade inválida: use de 1 a 500 lacres por lote.' USING ERRCODE = 'check_violation';
  END IF;

  SELECT array_agg(format('IC-%s-%s', v_ano, lpad(nextval('lacre_numero_seq')::text, 6, '0')) ORDER BY g)
    INTO v_numeros FROM generate_series(1, p_quantidade) g;
  v_codigo := format('L-%s-%s', v_ano, lpad(nextval('lote_lacre_seq')::text, 4, '0'));

  INSERT INTO lote_lacre (codigo, quantidade, primeiro_numero, ultimo_numero, gerado_por)
  VALUES (v_codigo, p_quantidade, v_numeros[1], v_numeros[p_quantidade], p_usuario)
  RETURNING id INTO v_lote;

  INSERT INTO lacre (numero, emissor, lote_id, status)
  SELECT n, 'instituto', v_lote, 'disponivel' FROM unnest(v_numeros) n;

  RETURN v_lote;
END $$;

-- 4.2 Verificação de integridade sob demanda (RF21, RF22). Recalcula o hash de
--     cada registro, confere o elo com o anterior e a sequência, grava o resultado
--     e devolve o id da verificação.
CREATE FUNCTION verificar_cadeia(p_evidencia uuid, p_usuario uuid) RETURNS uuid
LANGUAGE plpgsql AS $$
DECLARE
  r              cadeia_custodia%ROWTYPE;
  v_id           uuid := gen_random_uuid();
  v_esperado_ant char(64) := repeat('0', 64);
  v_esperada_seq integer := 1;
  v_total        integer := 0;
  v_calc         char(64);
  v_div          jsonb := '[]'::jsonb;
  v_ultimo       char(64);
BEGIN
  FOR r IN SELECT * FROM cadeia_custodia WHERE evidencia_id = p_evidencia ORDER BY sequencia LOOP
    v_total := v_total + 1;
    IF r.sequencia <> v_esperada_seq THEN
      v_div := v_div || jsonb_build_object('seq', r.sequencia, 'id', r.id, 'tipo', 'sequencia_quebrada');
    END IF;
    IF r.hash_anterior <> v_esperado_ant THEN
      v_div := v_div || jsonb_build_object('seq', r.sequencia, 'id', r.id, 'tipo', 'elo_quebrado',
                                           'armazenado', r.hash_anterior, 'recalculado', v_esperado_ant);
    END IF;
    v_calc := cadeia_calcular_hash(r);
    IF v_calc <> r.hash_registro THEN
      v_div := v_div || jsonb_build_object('seq', r.sequencia, 'id', r.id, 'tipo', 'conteudo_alterado',
                                           'armazenado', r.hash_registro, 'recalculado', v_calc);
    END IF;
    v_esperado_ant := r.hash_registro;
    v_esperada_seq := r.sequencia + 1;
    v_ultimo       := r.hash_registro;
  END LOOP;

  INSERT INTO verificacao_integridade (id, evidencia_id, executada_por, total_registros, registros_divergentes, hash_ultimo_registro)
  VALUES (v_id, p_evidencia, p_usuario, v_total,
          (SELECT count(DISTINCT (d->>'seq')) FROM jsonb_array_elements(v_div) d), v_ultimo);

  INSERT INTO verificacao_divergencia (verificacao_id, sequencia, cadeia_id, tipo, hash_armazenado, hash_recalculado)
  SELECT v_id, (d->>'seq')::int, (d->>'id')::uuid, (d->>'tipo')::tipo_divergencia, d->>'armazenado', d->>'recalculado'
    FROM jsonb_array_elements(v_div) d;

  RETURN v_id;
END $$;

-- =============================================================================
-- 5. VISÕES
-- =============================================================================

-- Situação de cada evidência com o alerta de lacre (RF07b) e a última verificação (RF23).
CREATE VIEW v_evidencia_situacao AS
SELECT e.id, e.codigo, e.tipo, e.descricao, e.status,
       e.setor_atual_id, e.setor_pendente_id, e.destino_externo_nome, e.perito_analisando_id,
       la.numero AS lacre_ativo_numero,
       (EXISTS (SELECT 1 FROM lacre l WHERE l.evidencia_id = e.id) AND la.id IS NULL
        AND e.status <> 'devolvida') AS bloqueada_sem_lacre,
       ult.sequencia AS ultima_sequencia, ult.acao AS ultima_acao, ult.data_hora AS ultima_movimentacao_em,
       vi.executada_em AS ultima_verificacao_em, vi.integra AS ultima_verificacao_integra
  FROM evidencia e
  LEFT JOIN lacre la ON la.evidencia_id = e.id AND la.status = 'vinculado'
  LEFT JOIN LATERAL (SELECT c.sequencia, c.acao, c.data_hora FROM cadeia_custodia c
                      WHERE c.evidencia_id = e.id ORDER BY c.sequencia DESC LIMIT 1) ult ON true
  LEFT JOIN LATERAL (SELECT v.executada_em, v.integra FROM verificacao_integridade v
                      WHERE v.evidencia_id = e.id ORDER BY v.executada_em DESC LIMIT 1) vi ON true;

-- Estoque de lacres por status e emissor (RF06b).
CREATE VIEW v_estoque_lacres AS
SELECT emissor, status, count(*) AS quantidade FROM lacre GROUP BY emissor, status;

-- =============================================================================
-- 6. ÍNDICES (os de unicidade estão junto das tabelas)
-- =============================================================================
CREATE INDEX usuario_setor_idx           ON usuario (setor_id) WHERE ativo;
CREATE INDEX evidencia_status_idx        ON evidencia (status);
CREATE INDEX evidencia_setor_atual_idx   ON evidencia (setor_atual_id);
CREATE INDEX evidencia_pendente_idx      ON evidencia (setor_pendente_id) WHERE status = 'em_transito';
CREATE INDEX evidencia_perito_idx        ON evidencia (perito_analisando_id) WHERE status = 'em_analise';
CREATE INDEX evidencia_ocorrencia_idx    ON evidencia (ocorrencia_id);
CREATE INDEX evidencia_coletado_em_idx   ON evidencia (coletado_em DESC);
CREATE INDEX ocorrencia_bo_numero_idx    ON ocorrencia_bo (upper(numero_bo));
CREATE INDEX lacre_evidencia_idx         ON lacre (evidencia_id);
CREATE INDEX lacre_estoque_idx           ON lacre (status, emissor);
CREATE INDEX lacre_lote_idx              ON lacre (lote_id) WHERE status = 'disponivel';
CREATE INDEX ref_externa_lacre_idx       ON lacre_referencia_externa (lacre_id);
CREATE INDEX cadeia_registrado_por_idx   ON cadeia_custodia (registrado_por);
CREATE INDEX cadeia_data_hora_idx        ON cadeia_custodia (data_hora);
CREATE INDEX verificacao_evidencia_idx   ON verificacao_integridade (evidencia_id, executada_em DESC);
CREATE INDEX token_revogado_expira_idx   ON token_revogado (expira_em);
CREATE INDEX log_acesso_evidencia_idx    ON log_acesso (evidencia_id, ocorrido_em DESC);
CREATE INDEX log_acesso_usuario_idx      ON log_acesso (usuario_id, ocorrido_em DESC);

-- =============================================================================
-- 7. PAPÉIS E PERMISSÕES
--    custodia_owner: dono das tabelas (só para migrações).
--    custodia_app:   usuário com que a API se conecta. Sem UPDATE/DELETE onde o
--                    log é imutável e sem DELETE em nada que seja prova.
--    custodia_leitura: consultas e relatórios.
--    Crie os logins depois, por exemplo:
--      CREATE ROLE api_login LOGIN PASSWORD '...' IN ROLE custodia_app;
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'custodia_app')     THEN CREATE ROLE custodia_app NOLOGIN;     END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'custodia_leitura') THEN CREATE ROLE custodia_leitura NOLOGIN; END IF;
END $$;

REVOKE ALL ON ALL TABLES    IN SCHEMA custodia FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA custodia FROM PUBLIC;
GRANT USAGE ON SCHEMA custodia TO custodia_app, custodia_leitura;

-- Leitura geral
GRANT SELECT ON ALL TABLES IN SCHEMA custodia TO custodia_app, custodia_leitura;

-- Cadastros que mudam (sem DELETE, exceto setor sem uso e tokens expirados)
GRANT INSERT, UPDATE         ON setor, usuario, ocorrencia, evidencia, lacre TO custodia_app;
GRANT DELETE                 ON setor, token_revogado, ocorrencia_bo          TO custodia_app;
GRANT INSERT                 ON ocorrencia_bo, token_revogado                 TO custodia_app;

-- Somente inserção (RNF03)
GRANT INSERT ON cadeia_custodia, lacre_referencia_externa, log_acesso TO custodia_app;

-- Lotes e verificações só pelas funções
GRANT USAGE ON SEQUENCE lacre_numero_seq, lote_lacre_seq TO custodia_app;
GRANT INSERT ON lote_lacre, verificacao_integridade, verificacao_divergencia TO custodia_app;
GRANT EXECUTE ON FUNCTION gerar_lote_lacres(integer, uuid), verificar_cadeia(uuid, uuid),
                          cadeia_conteudo_canonico(cadeia_custodia), cadeia_calcular_hash(cadeia_custodia)
  TO custodia_app;
GRANT EXECUTE ON FUNCTION cadeia_conteudo_canonico(cadeia_custodia), cadeia_calcular_hash(cadeia_custodia)
  TO custodia_leitura;
-- Funções de gatilho precisam estar executáveis por quem dispara o gatilho.
GRANT EXECUTE ON FUNCTION tg_atualizado_em(), tg_somente_insercao(), tg_cadeia_antes_inserir(),
                          tg_lacre_ciclo_de_vida(), tg_evidencia_protecao() TO custodia_app;

COMMIT;
