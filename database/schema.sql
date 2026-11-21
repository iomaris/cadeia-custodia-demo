-- =============================================================================
-- Cadeia de Custódia de Evidências (MVP) - esquema do banco de dados
-- PostgreSQL 14 ou superior (testado no 16). Nenhuma extensão é necessária.
--
-- Como aplicar (banco vazio):
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f schema.sql
--
-- Organização do arquivo:
--   1. Esquema e regras de tipo
--   2. Tabelas
--   3. Funções de apoio e gatilhos (imutabilidade, hash chain, regras de lacre)
--   4. Funções de negócio (gerar lote de lacres, verificar integridade)
--   5. Visões
--   6. Índices
--   7. Papéis e permissões
--   8. Dicionário no próprio banco (COMMENT ON)
-- =============================================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS custodia;
SET search_path = custodia, public;

-- =============================================================================
-- 1. REGRAS DE TIPO USADAS EM TODO O ESQUEMA
--
--   uuid                      identificadores (chaves primárias e estrangeiras)
--   varchar(n)                texto com tamanho máximo conhecido (nomes, códigos,
--                             e-mail, endereços); o n é o limite real do campo
--   varchar(30) + CHECK IN    listas fixas de valores (perfil, tipo, situação,
--                             ação...). O valor gravado é sempre minúsculo, sem
--                             acento e com _ no lugar de espaço; a tela mostra o
--                             rótulo em português
--   text                      texto livre e longo, sem limite natural (descrição,
--                             observação, motivo, justificativa, navegador)
--   char(64)                  hash SHA-256 em hexadecimal: sempre 64 caracteres
--   timestamp with time zone  data e hora (timestamptz); gravado em UTC e mostrado
--                             no fuso de quem lê (Manaus, UTC-4)
--   numeric(9,6)              latitude e longitude em graus, 6 casas decimais
--   integer / bigint          contagens e números; bigint só no log de acesso
--   boolean                   sim/não
--   inet                      endereço IP (IPv4 ou IPv6)
-- =============================================================================

-- =============================================================================
-- 2. TABELAS
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 2.1 setor (RF10, RF11): setores do Instituto. Nunca é apagado se estiver em uso;
--     desative com ativo = false.
-- -----------------------------------------------------------------------------
CREATE TABLE setor (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  nome                        varchar(120)  NOT NULL CHECK (length(btrim(nome)) >= 2),
  ativo                       boolean       NOT NULL DEFAULT true,
  criado_em                   timestamptz   NOT NULL DEFAULT now(),
  atualizado_em               timestamptz   NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX setor_nome_uk ON setor (lower(btrim(nome)));

-- -----------------------------------------------------------------------------
-- 2.2 usuario (RF01, RF11, RF16)
-- -----------------------------------------------------------------------------
CREATE TABLE usuario (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  nome                        varchar(160)  NOT NULL CHECK (length(btrim(nome)) >= 2),
  matricula                   varchar(30)   NOT NULL CHECK (length(btrim(matricula)) >= 1),
  email                       varchar(254)  NOT NULL CHECK (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  senha_hash                  varchar(255)  NOT NULL CHECK (senha_hash ~ '^\$(2[aby]|argon2id)\$'),
  perfil                      varchar(30)   NOT NULL DEFAULT 'normal'
                              CONSTRAINT usuario_perfil_valores CHECK (perfil IN ('perito', 'normal', 'administrador')),
  setor_id                    uuid          NOT NULL REFERENCES setor (id) ON DELETE RESTRICT,
  ativo                       boolean       NOT NULL DEFAULT true,
  ultimo_login_em             timestamptz,
  criado_em                   timestamptz   NOT NULL DEFAULT now(),
  atualizado_em               timestamptz   NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX usuario_matricula_uk ON usuario (lower(btrim(matricula)));
CREATE UNIQUE INDEX usuario_email_uk     ON usuario (lower(btrim(email)));

-- -----------------------------------------------------------------------------
-- 2.3 token_revogado (RF01 logout): o JWT não fica guardado no banco; para o
--     logout valer antes de o token expirar, o identificador do token (jti) entra
--     nesta lista até a data de expiração.
-- -----------------------------------------------------------------------------
CREATE TABLE token_revogado (
  id_token                    uuid          PRIMARY KEY,
  usuario_id                  uuid          NOT NULL REFERENCES usuario (id) ON DELETE CASCADE,
  expira_em                   timestamptz   NOT NULL,
  revogado_em                 timestamptz   NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 2.4 ocorrencia + ocorrencia_bo (RF02b ocorrência, RF02c, RF02d, RF02e)
-- -----------------------------------------------------------------------------
CREATE TABLE ocorrencia (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  codigo_gigante              varchar(40)   CHECK (codigo_gigante IS NULL OR length(btrim(codigo_gigante)) > 0),
  numero_oficio               varchar(40),
  delegacia_origem            varchar(160),
  tipo_crime                  varchar(30)
                              CONSTRAINT ocorrencia_tipo_crime_valores CHECK (tipo_crime IN (
                                'homicidio', 'roubo', 'furto', 'trafico_drogas', 'lesao_corporal',
                                'crime_cibernetico', 'outro')),
  data_hora_ocorrencia        timestamptz,
  endereco_ocorrencia         varchar(300),
  observacao                  text,
  criado_por_id               uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  criado_em                   timestamptz   NOT NULL DEFAULT now(),
  atualizado_em               timestamptz   NOT NULL DEFAULT now(),
  -- RF02e: uma ocorrência só é criada se tiver ao menos um dado preenchido.
  CONSTRAINT ocorrencia_nao_vazia CHECK (
    codigo_gigante IS NOT NULL OR numero_oficio IS NOT NULL OR delegacia_origem IS NOT NULL
    OR tipo_crime IS NOT NULL OR data_hora_ocorrencia IS NOT NULL OR endereco_ocorrencia IS NOT NULL
    OR observacao IS NOT NULL
  )
);
-- RF02c/RF02d: o código GIGANTE identifica a ocorrência (busca sem diferenciar maiúsculas).
CREATE UNIQUE INDEX ocorrencia_gigante_uk ON ocorrencia (upper(btrim(codigo_gigante)))
  WHERE codigo_gigante IS NOT NULL;

CREATE TABLE ocorrencia_bo (
  ocorrencia_id               uuid          NOT NULL REFERENCES ocorrencia (id) ON DELETE CASCADE,
  numero_bo                   varchar(40)   NOT NULL CHECK (length(btrim(numero_bo)) > 0),
  adicionado_por_id           uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  adicionado_em               timestamptz   NOT NULL DEFAULT now(),
  PRIMARY KEY (ocorrencia_id, numero_bo)
);

-- -----------------------------------------------------------------------------
-- 2.5 evidencia (RF02, RF03, RF12, RF13, RF17-RF19)
--     As colunas de situação (situacao, setor_atual_id...) são uma cópia de leitura
--     rápida, atualizada pela API na mesma transação que grava a cadeia.
--     coletado_em é o momento do cadastro (não há coluna criado_em separada).
-- -----------------------------------------------------------------------------
CREATE TABLE evidencia (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  codigo                      varchar(40)   NOT NULL CHECK (length(btrim(codigo)) >= 1),
  tipo_evidencia              varchar(30)   NOT NULL
                              CONSTRAINT evidencia_tipo_evidencia_valores CHECK (tipo_evidencia IN (
                                'arma_de_fogo', 'projetil_municao', 'arma_branca', 'dispositivo_eletronico',
                                'documento', 'material_biologico', 'substancia_entorpecente',
                                'vestigio_papiloscopico', 'outro')),
  descricao                   text          NOT NULL CHECK (length(btrim(descricao)) > 0),
  -- Local onde foi encontrada (RF02: endereço + localização geográfica)
  endereco_coleta             varchar(300)  NOT NULL CHECK (length(btrim(endereco_coleta)) > 0),
  latitude_coleta             numeric(9,6)  CHECK (latitude_coleta BETWEEN -90 AND 90),
  longitude_coleta            numeric(9,6)  CHECK (longitude_coleta BETWEEN -180 AND 180),
  ocorrencia_id               uuid          REFERENCES ocorrencia (id) ON DELETE RESTRICT,  -- opcional (RF02e)
  -- Foto e integridade do arquivo (RF02, RF03)
  foto_caminho_arquivo        varchar(500)  NOT NULL,
  foto_nome_arquivo           varchar(255)  NOT NULL,
  foto_tipo_arquivo           varchar(30)   NOT NULL
                              CONSTRAINT evidencia_foto_tipo_arquivo_valores CHECK (foto_tipo_arquivo IN (
                                'image/jpeg', 'image/png', 'image/heic', 'image/webp')),
  foto_tamanho_bytes          integer       NOT NULL CHECK (foto_tamanho_bytes > 0),
  foto_hash_sha256            char(64)      NOT NULL CHECK (foto_hash_sha256 ~ '^[0-9a-f]{64}$'),
  -- Coleta
  coletado_por_id             uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  coletado_em                 timestamptz   NOT NULL DEFAULT now(),
  -- Situação atual (cópia de leitura rápida da cadeia)
  situacao                    varchar(30)   NOT NULL DEFAULT 'coletada'
                              CONSTRAINT evidencia_situacao_valores CHECK (situacao IN (
                                'coletada', 'em_transito', 'recebida', 'em_analise', 'analisada',
                                'armazenada', 'em_destino_externo', 'devolvida')),
  setor_atual_id              uuid          REFERENCES setor (id) ON DELETE RESTRICT,
  setor_destino_pendente_id   uuid          REFERENCES setor (id) ON DELETE RESTRICT,  -- destino interno em trânsito
  destino_externo_nome        varchar(160),                                            -- destino externo (RF13b)
  destino_externo_endereco    varchar(300),
  perito_responsavel_id       uuid          REFERENCES usuario (id) ON DELETE RESTRICT,
  atualizado_em               timestamptz   NOT NULL DEFAULT now(),

  CONSTRAINT evidencia_coordenadas_juntas CHECK ((latitude_coleta IS NULL) = (longitude_coleta IS NULL)),
  CONSTRAINT evidencia_destino_externo_completo CHECK ((destino_externo_nome IS NULL) = (destino_externo_endereco IS NULL)),
  -- RF13: em trânsito não há setor atual nem responsável individual, só o destino.
  CONSTRAINT evidencia_em_transito CHECK (
    situacao <> 'em_transito'
    OR (setor_atual_id IS NULL AND perito_responsavel_id IS NULL
        AND ((setor_destino_pendente_id IS NOT NULL) <> (destino_externo_nome IS NOT NULL)))
  ),
  CONSTRAINT evidencia_pendente_so_em_transito CHECK (setor_destino_pendente_id IS NULL OR situacao = 'em_transito'),
  -- RF17/RF18: em análise exige setor e perito; fora dela, nenhum perito.
  CONSTRAINT evidencia_em_analise CHECK (
    (situacao = 'em_analise' AND perito_responsavel_id IS NOT NULL AND setor_atual_id IS NOT NULL)
    OR (situacao <> 'em_analise' AND perito_responsavel_id IS NULL)
  ),
  CONSTRAINT evidencia_no_setor CHECK (situacao NOT IN ('recebida', 'analisada', 'armazenada') OR setor_atual_id IS NOT NULL),
  CONSTRAINT evidencia_destino_externo CHECK (situacao <> 'em_destino_externo' OR destino_externo_nome IS NOT NULL),
  CONSTRAINT evidencia_devolvida CHECK (situacao <> 'devolvida' OR (setor_atual_id IS NULL AND setor_destino_pendente_id IS NULL))
);
CREATE UNIQUE INDEX evidencia_codigo_uk ON evidencia (upper(btrim(codigo)));

-- -----------------------------------------------------------------------------
-- 2.6 lote_lacre (RF04, RF06): lotes impressos com antecedência pelo Instituto.
-- -----------------------------------------------------------------------------
CREATE SEQUENCE lote_lacre_seq;
CREATE SEQUENCE lacre_numero_seq;

CREATE TABLE lote_lacre (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  codigo_lote                 varchar(20)   NOT NULL UNIQUE,                     -- ex.: L-2026-0001
  quantidade                  integer       NOT NULL CHECK (quantidade BETWEEN 1 AND 500),
  primeiro_numero_lacre       varchar(60)   NOT NULL,
  ultimo_numero_lacre         varchar(60)   NOT NULL,
  gerado_por_id               uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  gerado_em                   timestamptz   NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 2.7 lacre (RF04-RF07c): lacre de cada evidência. Inclui os lacres do Instituto
--     (com lote e QR code) e os lacres externos usados como lacre principal
--     (RF05d: fabricante, SENASP/MJ, SSP...), que não têm lote.
--     O QR code codifica só numero_lacre (RF04c); por isso não há coluna qr_payload.
-- -----------------------------------------------------------------------------
CREATE TABLE lacre (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  numero_lacre                varchar(60)   NOT NULL CHECK (length(btrim(numero_lacre)) >= 1),
  emissor                     varchar(30)   NOT NULL
                              CONSTRAINT lacre_emissor_valores CHECK (emissor IN (
                                'instituto', 'ssp', 'senasp_mj', 'tribunal_justica', 'policia_federal',
                                'pericia_externa', 'fabricante', 'outro')),
  lote_id                     uuid          REFERENCES lote_lacre (id) ON DELETE RESTRICT,
  situacao                    varchar(30)   NOT NULL DEFAULT 'disponivel'
                              CONSTRAINT lacre_situacao_valores CHECK (situacao IN ('disponivel', 'vinculado', 'rompido')),
  evidencia_id                uuid          REFERENCES evidencia (id) ON DELETE RESTRICT,
  hash_foto_na_associacao     char(64)      CHECK (hash_foto_na_associacao ~ '^[0-9a-f]{64}$'),
  cadastrado_por_id           uuid          REFERENCES usuario (id) ON DELETE RESTRICT,  -- quem cadastrou um lacre externo
  cadastrado_em               timestamptz   NOT NULL DEFAULT now(),
  vinculado_por_id            uuid          REFERENCES usuario (id) ON DELETE RESTRICT,
  vinculado_em                timestamptz,
  rompido_por_id              uuid          REFERENCES usuario (id) ON DELETE RESTRICT,
  motivo_rompimento           text,
  rompido_em                  timestamptz,

  -- RF04d: só o Instituto tem lote; lacre externo nunca tem lote.
  CONSTRAINT lacre_lote_so_instituto CHECK ((emissor = 'instituto') = (lote_id IS NOT NULL)),
  CONSTRAINT lacre_externo_tem_autor CHECK (emissor = 'instituto' OR cadastrado_por_id IS NOT NULL),
  -- RF04b: disponível = sem evidência e sem dados de vínculo.
  CONSTRAINT lacre_disponivel CHECK (
    situacao <> 'disponivel'
    OR (evidencia_id IS NULL AND vinculado_por_id IS NULL AND vinculado_em IS NULL AND rompido_por_id IS NULL)
  ),
  -- RF05b: vinculado guarda evidência, autor, data e o hash da foto no momento.
  CONSTRAINT lacre_vinculado CHECK (
    situacao = 'disponivel'
    OR (evidencia_id IS NOT NULL AND vinculado_por_id IS NOT NULL AND vinculado_em IS NOT NULL
        AND hash_foto_na_associacao IS NOT NULL)
  ),
  -- RF07: rompimento exige responsável, motivo e data.
  CONSTRAINT lacre_rompido CHECK (
    (situacao = 'rompido') = (rompido_por_id IS NOT NULL AND rompido_em IS NOT NULL
                             AND motivo_rompimento IS NOT NULL AND length(btrim(motivo_rompimento)) > 0)
  )
);
-- RNF05, RF05e: número único no sistema inteiro, inclusive externos e histórico.
CREATE UNIQUE INDEX lacre_numero_uk ON lacre (upper(btrim(numero_lacre)));
-- RF05c/RF07b: no máximo um lacre ativo por evidência.
CREATE UNIQUE INDEX lacre_um_ativo_por_evidencia ON lacre (evidencia_id) WHERE situacao = 'vinculado';

-- -----------------------------------------------------------------------------
-- 2.8 lacre_referencia_externa (RF04e): lacres de outras instituições que já
--     estavam na evidência, ligados ao lacre do Instituto como registro histórico.
--     Corresponde à entidade "LacreExterno" do documento.
-- -----------------------------------------------------------------------------
CREATE TABLE lacre_referencia_externa (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  lacre_id                    uuid          NOT NULL REFERENCES lacre (id) ON DELETE RESTRICT,
  emissor                     varchar(30)   NOT NULL
                              CONSTRAINT ref_externa_emissor_valores CHECK (emissor IN (
                                'ssp', 'senasp_mj', 'tribunal_justica', 'policia_federal',
                                'pericia_externa', 'fabricante', 'outro')),
  numero_lacre_externo        varchar(60)   NOT NULL CHECK (length(btrim(numero_lacre_externo)) > 0),
  observacao                  text,
  associado_por_id            uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  associado_em                timestamptz   NOT NULL DEFAULT now(),
  UNIQUE (lacre_id, emissor, numero_lacre_externo)
);

-- -----------------------------------------------------------------------------
-- 2.9 cadeia_custodia (RF08-RF09, RF12-RF20, RNF03, RNF04)
--     Log somente de inserção. numero_sequencia, hash_registro_anterior,
--     data_hora_registro e hash_registro são preenchidos pelo gatilho; valores
--     enviados pela aplicação são ignorados.
-- -----------------------------------------------------------------------------
CREATE TABLE cadeia_custodia (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  evidencia_id                uuid          NOT NULL REFERENCES evidencia (id) ON DELETE RESTRICT,
  numero_sequencia            integer       NOT NULL CHECK (numero_sequencia >= 1),
  acao                        varchar(30)   NOT NULL
                              CONSTRAINT cadeia_acao_valores CHECK (acao IN (
                                'coletado', 'encaminhado', 'recebido', 'chegada_destino_externo',
                                'em_analise', 'analisado', 'armazenado', 'devolvido',
                                'lacre_associado', 'lacre_rompido')),
  registrado_por_id           uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT, -- usuário logado
  nome_responsavel_posse      varchar(160)  NOT NULL CHECK (length(btrim(nome_responsavel_posse)) > 0),
  setor_atual_id              uuid          REFERENCES setor (id) ON DELETE RESTRICT,   -- onde a ação aconteceu
  setor_destino_id            uuid          REFERENCES setor (id) ON DELETE RESTRICT,   -- encaminhado/armazenado (RF08b)
  destino_externo_nome        varchar(160),                                             -- RF13b
  destino_externo_endereco    varchar(300),
  endereco_local              varchar(300),                                             -- endereço livre (coleta, destino externo)
  lacre_id                    uuid          REFERENCES lacre (id) ON DELETE RESTRICT,   -- eventos de lacre
  data_hora_registro          timestamptz   NOT NULL DEFAULT now(),                     -- hora do servidor
  observacao                  text,
  -- Localização real do dispositivo (RF02b local, RF13c, RF13f)
  gps_obtido                  boolean       NOT NULL DEFAULT false,
  gps_latitude                numeric(9,6)  CHECK (gps_latitude BETWEEN -90 AND 90),
  gps_longitude               numeric(9,6)  CHECK (gps_longitude BETWEEN -180 AND 180),
  gps_precisao_metros         numeric(8,1)  CHECK (gps_precisao_metros >= 0),
  -- Cadastro fora do local indicado (RF02b local), só na ação "coletado"
  cadastro_fora_do_local      boolean,
  justificativa_fora_local    text,
  -- Hash chain (RF09)
  hash_registro_anterior      char(64)      NOT NULL CHECK (hash_registro_anterior ~ '^[0-9a-f]{64}$'),
  hash_registro               char(64)      NOT NULL CHECK (hash_registro ~ '^[0-9a-f]{64}$'),

  UNIQUE (evidencia_id, numero_sequencia),
  UNIQUE (evidencia_id, hash_registro_anterior),   -- impede duas ramificações a partir do mesmo registro
  UNIQUE (hash_registro),
  CONSTRAINT cadeia_genese CHECK ((numero_sequencia = 1) = (hash_registro_anterior = repeat('0', 64))),
  CONSTRAINT cadeia_coordenadas CHECK (
    (gps_obtido AND gps_latitude IS NOT NULL AND gps_longitude IS NOT NULL)
    OR (NOT gps_obtido AND gps_latitude IS NULL AND gps_longitude IS NULL AND gps_precisao_metros IS NULL)
  ),
  CONSTRAINT cadeia_destino_externo_completo CHECK ((destino_externo_nome IS NULL) = (destino_externo_endereco IS NULL)),
  -- Regras por ação
  CONSTRAINT cadeia_coletado CHECK (
    acao <> 'coletado' OR (numero_sequencia = 1 AND endereco_local IS NOT NULL AND cadastro_fora_do_local IS NOT NULL)
  ),
  CONSTRAINT cadeia_so_coleta_e_primeira CHECK (numero_sequencia <> 1 OR acao = 'coletado'),
  CONSTRAINT cadeia_justificativa CHECK (
    (cadastro_fora_do_local IS NULL AND justificativa_fora_local IS NULL)
    OR (cadastro_fora_do_local = false AND justificativa_fora_local IS NULL)
    OR (cadastro_fora_do_local = true AND length(btrim(coalesce(justificativa_fora_local, ''))) > 0)
  ),
  CONSTRAINT cadeia_fora_do_local_so_na_coleta CHECK (acao = 'coletado' OR cadastro_fora_do_local IS NULL),
  CONSTRAINT cadeia_encaminhado CHECK (
    acao <> 'encaminhado' OR ((setor_destino_id IS NOT NULL) <> (destino_externo_nome IS NOT NULL))
  ),
  CONSTRAINT cadeia_armazenado CHECK (acao <> 'armazenado' OR setor_destino_id IS NOT NULL),
  CONSTRAINT cadeia_recebido CHECK (acao NOT IN ('recebido', 'em_analise', 'analisado') OR setor_atual_id IS NOT NULL),
  CONSTRAINT cadeia_chegada_externa CHECK (acao <> 'chegada_destino_externo' OR endereco_local IS NOT NULL),
  CONSTRAINT cadeia_devolvido CHECK (acao <> 'devolvido' OR endereco_local IS NOT NULL OR destino_externo_nome IS NOT NULL),
  CONSTRAINT cadeia_evento_lacre CHECK ((acao IN ('lacre_associado', 'lacre_rompido')) = (lacre_id IS NOT NULL))
);

-- -----------------------------------------------------------------------------
-- 2.10 verificacao_integridade + verificacao_divergencia (RF21-RF23)
-- -----------------------------------------------------------------------------
CREATE TABLE verificacao_integridade (
  id                          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  evidencia_id                uuid          NOT NULL REFERENCES evidencia (id) ON DELETE RESTRICT,
  executada_por_id            uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  executada_em                timestamptz   NOT NULL DEFAULT now(),
  total_registros             integer       NOT NULL CHECK (total_registros >= 0),
  registros_divergentes       integer       NOT NULL CHECK (registros_divergentes >= 0),
  cadeia_integra              boolean       GENERATED ALWAYS AS (registros_divergentes = 0) STORED,
  hash_ultimo_registro        char(64)      CHECK (hash_ultimo_registro ~ '^[0-9a-f]{64}$'),
  CONSTRAINT verificacao_divergentes_ate_total CHECK (registros_divergentes <= total_registros),
  CONSTRAINT verificacao_hash_se_tem_registros CHECK ((total_registros = 0) = (hash_ultimo_registro IS NULL))
);

CREATE TABLE verificacao_divergencia (
  verificacao_id              uuid          NOT NULL REFERENCES verificacao_integridade (id) ON DELETE RESTRICT,
  numero_sequencia            integer       NOT NULL CHECK (numero_sequencia >= 1),
  cadeia_custodia_id          uuid          NOT NULL REFERENCES cadeia_custodia (id) ON DELETE RESTRICT,
  tipo_divergencia            varchar(30)   NOT NULL
                              CONSTRAINT divergencia_tipo_valores CHECK (tipo_divergencia IN (
                                'conteudo_alterado', 'elo_quebrado', 'sequencia_quebrada')),
  hash_armazenado             char(64)      CHECK (hash_armazenado ~ '^[0-9a-f]{64}$'),
  hash_recalculado            char(64)      CHECK (hash_recalculado ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (verificacao_id, numero_sequencia, tipo_divergencia),
  -- Os dois hashes aparecem juntos, só nas divergências de conteúdo e de elo.
  CONSTRAINT divergencia_hashes CHECK (
    (tipo_divergencia = 'sequencia_quebrada' AND hash_armazenado IS NULL AND hash_recalculado IS NULL)
    OR (tipo_divergencia <> 'sequencia_quebrada' AND hash_armazenado IS NOT NULL AND hash_recalculado IS NOT NULL)
  )
);

-- -----------------------------------------------------------------------------
-- 2.11 log_acesso (RNF-S7): quem consultou ou exportou cada evidência.
-- -----------------------------------------------------------------------------
CREATE TABLE log_acesso (
  id                          bigint        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  usuario_id                  uuid          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
  evidencia_id                uuid          NOT NULL REFERENCES evidencia (id) ON DELETE RESTRICT,
  acao_acesso                 varchar(30)   NOT NULL
                              CONSTRAINT log_acesso_acao_valores CHECK (acao_acesso IN (
                                'visualizou_evidencia', 'visualizou_cadeia', 'exportou_pdf',
                                'exportou_csv', 'verificou_integridade')),
  endereco_ip                 inet,
  navegador                   text,
  ocorrido_em                 timestamptz   NOT NULL DEFAULT now()
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
--     Formato: hash_registro_anterior || '|' || texto JSON do array abaixo, nesta ordem.
CREATE FUNCTION cadeia_conteudo_canonico(r cadeia_custodia) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT r.hash_registro_anterior || '|' || json_build_array(
    'v1',                                    -- versão do formato
    r.id, r.evidencia_id, r.numero_sequencia, r.acao, r.registrado_por_id, r.nome_responsavel_posse,
    r.setor_atual_id, r.setor_destino_id, r.destino_externo_nome, r.destino_externo_endereco,
    r.endereco_local, r.lacre_id,
    to_char(r.data_hora_registro AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    r.observacao, r.gps_obtido, r.gps_latitude::text, r.gps_longitude::text, r.gps_precisao_metros::text,
    r.cadastro_fora_do_local, r.justificativa_fora_local
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
  v_status      varchar(30);
  v_teve_lacre  boolean;
  v_lacre_ativo boolean;
BEGIN
  -- Trava a linha da evidência até o fim da transação.
  SELECT situacao INTO v_status FROM evidencia WHERE id = NEW.evidencia_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Evidência % não existe.', NEW.evidencia_id USING ERRCODE = 'foreign_key_violation';
  END IF;

  SELECT * INTO v_ultimo FROM cadeia_custodia
   WHERE evidencia_id = NEW.evidencia_id ORDER BY numero_sequencia DESC LIMIT 1;

  IF FOUND THEN
    IF v_ultimo.acao = 'devolvido' THEN
      RAISE EXCEPTION 'A evidência foi devolvida; a cadeia está encerrada (RF13e).' USING ERRCODE = 'check_violation';
    END IF;
    NEW.numero_sequencia     := v_ultimo.numero_sequencia + 1;
    NEW.hash_registro_anterior := v_ultimo.hash_registro;
  ELSE
    NEW.numero_sequencia     := 1;
    NEW.hash_registro_anterior := repeat('0', 64);
  END IF;

  -- RF07b: lacre rompido sem substituto bloqueia tudo, exceto eventos de lacre.
  IF NEW.acao NOT IN ('lacre_associado', 'lacre_rompido') THEN
    SELECT EXISTS (SELECT 1 FROM lacre WHERE evidencia_id = NEW.evidencia_id),
           EXISTS (SELECT 1 FROM lacre WHERE evidencia_id = NEW.evidencia_id AND situacao = 'vinculado')
      INTO v_teve_lacre, v_lacre_ativo;
    IF v_teve_lacre AND NOT v_lacre_ativo THEN
      RAISE EXCEPTION 'Evidência sem lacre ativo: associe um novo lacre antes de qualquer movimentação (RF07b).'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  NEW.data_hora_registro     := now();                 -- hora do servidor, nunca do dispositivo
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
    IF NEW.emissor = 'instituto' AND NEW.situacao <> 'disponivel' THEN
      RAISE EXCEPTION 'Lacre do Instituto nasce disponível (RF04b).' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.situacao = 'rompido' THEN
      RAISE EXCEPTION 'Um lacre não pode ser cadastrado já rompido.' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.numero_lacre IS DISTINCT FROM OLD.numero_lacre OR NEW.emissor IS DISTINCT FROM OLD.emissor
     OR NEW.lote_id IS DISTINCT FROM OLD.lote_id OR NEW.cadastrado_em IS DISTINCT FROM OLD.cadastrado_em THEN
    RAISE EXCEPTION 'Número, emissor e lote do lacre não podem ser alterados.' USING ERRCODE = 'check_violation';
  END IF;

  IF OLD.situacao = 'rompido' THEN
    RAISE EXCEPTION 'O lacre % foi rompido e não pode ser reutilizado (RF05c).', OLD.numero_lacre USING ERRCODE = 'check_violation';
  END IF;

  IF OLD.situacao = 'vinculado' THEN
    IF NEW.situacao = 'disponivel' THEN
      RAISE EXCEPTION 'Um lacre vinculado não volta a ficar disponível.' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.evidencia_id IS DISTINCT FROM OLD.evidencia_id
       OR NEW.vinculado_por_id IS DISTINCT FROM OLD.vinculado_por_id
       OR NEW.vinculado_em IS DISTINCT FROM OLD.vinculado_em
       OR NEW.hash_foto_na_associacao IS DISTINCT FROM OLD.hash_foto_na_associacao THEN
      RAISE EXCEPTION 'O lacre % já está vinculado à outra evidência (RF05c).', OLD.numero_lacre USING ERRCODE = 'check_violation';
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
  IF OLD.situacao = 'devolvida' THEN
    RAISE EXCEPTION 'A evidência % foi devolvida e não pode mais ser alterada.', OLD.codigo USING ERRCODE = 'check_violation';
  END IF;
  -- Dados de identificação e da foto não mudam depois do cadastro.
  IF NEW.codigo IS DISTINCT FROM OLD.codigo
     OR NEW.foto_caminho_arquivo IS DISTINCT FROM OLD.foto_caminho_arquivo
     OR NEW.foto_nome_arquivo    IS DISTINCT FROM OLD.foto_nome_arquivo
     OR NEW.foto_tipo_arquivo    IS DISTINCT FROM OLD.foto_tipo_arquivo
     OR NEW.foto_tamanho_bytes   IS DISTINCT FROM OLD.foto_tamanho_bytes
     OR NEW.foto_hash_sha256     IS DISTINCT FROM OLD.foto_hash_sha256
     OR NEW.coletado_por_id      IS DISTINCT FROM OLD.coletado_por_id
     OR NEW.coletado_em          IS DISTINCT FROM OLD.coletado_em THEN
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
  IF NOT EXISTS (SELECT 1 FROM usuario WHERE id = p_usuario AND perfil = 'administrador' AND ativo) THEN
    RAISE EXCEPTION 'Só administradores geram lotes de lacres (RF04).' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_quantidade IS NULL OR p_quantidade NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'Quantidade inválida: use de 1 a 500 lacres por lote.' USING ERRCODE = 'check_violation';
  END IF;

  SELECT array_agg(format('IC-%s-%s', v_ano, lpad(nextval('lacre_numero_seq')::text, 6, '0')) ORDER BY g)
    INTO v_numeros FROM generate_series(1, p_quantidade) g;
  v_codigo := format('L-%s-%s', v_ano, lpad(nextval('lote_lacre_seq')::text, 4, '0'));

  INSERT INTO lote_lacre (codigo_lote, quantidade, primeiro_numero_lacre, ultimo_numero_lacre, gerado_por_id)
  VALUES (v_codigo, p_quantidade, v_numeros[1], v_numeros[p_quantidade], p_usuario)
  RETURNING id INTO v_lote;

  INSERT INTO lacre (numero_lacre, emissor, lote_id, situacao)
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
  FOR r IN SELECT * FROM cadeia_custodia WHERE evidencia_id = p_evidencia ORDER BY numero_sequencia LOOP
    v_total := v_total + 1;
    IF r.numero_sequencia <> v_esperada_seq THEN
      v_div := v_div || jsonb_build_object('seq', r.numero_sequencia, 'id', r.id, 'tipo', 'sequencia_quebrada');
    END IF;
    IF r.hash_registro_anterior <> v_esperado_ant THEN
      v_div := v_div || jsonb_build_object('seq', r.numero_sequencia, 'id', r.id, 'tipo', 'elo_quebrado',
                                           'armazenado', r.hash_registro_anterior, 'recalculado', v_esperado_ant);
    END IF;
    v_calc := cadeia_calcular_hash(r);
    IF v_calc <> r.hash_registro THEN
      v_div := v_div || jsonb_build_object('seq', r.numero_sequencia, 'id', r.id, 'tipo', 'conteudo_alterado',
                                           'armazenado', r.hash_registro, 'recalculado', v_calc);
    END IF;
    v_esperado_ant := r.hash_registro;
    v_esperada_seq := r.numero_sequencia + 1;
    v_ultimo       := r.hash_registro;
  END LOOP;

  INSERT INTO verificacao_integridade (id, evidencia_id, executada_por_id, total_registros, registros_divergentes, hash_ultimo_registro)
  VALUES (v_id, p_evidencia, p_usuario, v_total,
          (SELECT count(DISTINCT (d->>'seq')) FROM jsonb_array_elements(v_div) d), v_ultimo);

  INSERT INTO verificacao_divergencia (verificacao_id, numero_sequencia, cadeia_custodia_id, tipo_divergencia, hash_armazenado, hash_recalculado)
  SELECT v_id, (d->>'seq')::int, (d->>'id')::uuid, d->>'tipo', d->>'armazenado', d->>'recalculado'
    FROM jsonb_array_elements(v_div) d;

  RETURN v_id;
END $$;

-- =============================================================================
-- 5. VISÕES
-- =============================================================================

-- Situação de cada evidência com o alerta de lacre (RF07b) e a última verificação (RF23).
CREATE VIEW v_evidencia_situacao AS
SELECT e.id, e.codigo, e.tipo_evidencia, e.descricao, e.situacao,
       e.setor_atual_id, e.setor_destino_pendente_id, e.destino_externo_nome, e.perito_responsavel_id,
       la.numero_lacre AS lacre_ativo_numero,
       (EXISTS (SELECT 1 FROM lacre l WHERE l.evidencia_id = e.id) AND la.id IS NULL
        AND e.situacao <> 'devolvida') AS bloqueada_sem_lacre,
       ult.numero_sequencia AS ultima_sequencia, ult.acao AS ultima_acao, ult.data_hora_registro AS ultima_movimentacao_em,
       vi.executada_em AS ultima_verificacao_em, vi.cadeia_integra AS ultima_verificacao_integra
  FROM evidencia e
  LEFT JOIN lacre la ON la.evidencia_id = e.id AND la.situacao = 'vinculado'
  LEFT JOIN LATERAL (SELECT c.numero_sequencia, c.acao, c.data_hora_registro FROM cadeia_custodia c
                      WHERE c.evidencia_id = e.id ORDER BY c.numero_sequencia DESC LIMIT 1) ult ON true
  LEFT JOIN LATERAL (SELECT v.executada_em, v.cadeia_integra FROM verificacao_integridade v
                      WHERE v.evidencia_id = e.id ORDER BY v.executada_em DESC LIMIT 1) vi ON true;

-- Estoque de lacres por situação e emissor (RF06b).
CREATE VIEW v_estoque_lacres AS
SELECT emissor, situacao, count(*) AS quantidade FROM lacre GROUP BY emissor, situacao;

-- =============================================================================
-- 6. ÍNDICES (os de unicidade estão junto das tabelas)
-- =============================================================================
CREATE INDEX usuario_setor_idx           ON usuario (setor_id) WHERE ativo;
CREATE INDEX evidencia_situacao_idx      ON evidencia (situacao);
CREATE INDEX evidencia_setor_atual_idx   ON evidencia (setor_atual_id);
CREATE INDEX evidencia_pendente_idx      ON evidencia (setor_destino_pendente_id) WHERE situacao = 'em_transito';
CREATE INDEX evidencia_perito_idx        ON evidencia (perito_responsavel_id) WHERE situacao = 'em_analise';
CREATE INDEX evidencia_ocorrencia_idx    ON evidencia (ocorrencia_id);
CREATE INDEX evidencia_coletado_em_idx   ON evidencia (coletado_em DESC);
CREATE INDEX ocorrencia_bo_numero_idx    ON ocorrencia_bo (upper(numero_bo));
CREATE INDEX lacre_evidencia_idx         ON lacre (evidencia_id);
CREATE INDEX lacre_estoque_idx           ON lacre (situacao, emissor);
CREATE INDEX lacre_lote_idx              ON lacre (lote_id) WHERE situacao = 'disponivel';
CREATE INDEX ref_externa_lacre_idx       ON lacre_referencia_externa (lacre_id);
CREATE INDEX cadeia_registrado_por_idx   ON cadeia_custodia (registrado_por_id);
CREATE INDEX cadeia_data_hora_idx        ON cadeia_custodia (data_hora_registro);
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


-- =============================================================================
-- 8. DICIONÁRIO NO PRÓPRIO BANCO: descrição e requisitos de cada tabela e coluna
--    Gerado a partir de dicionario.py. Consulte com \d+ custodia.<tabela> no psql.
-- =============================================================================
COMMENT ON TABLE setor IS 'Setores do Instituto (Recepção, laboratórios, Depósito). Um setor em uso não é apagado, só desativado. Requisitos: RF10, RF11.';
COMMENT ON COLUMN setor.id IS 'Identificador do setor. Requisitos: RF10.';
COMMENT ON COLUMN setor.nome IS 'Nome do setor; de 2 a 120 caracteres; único sem diferenciar maiúsculas. Requisitos: RF10.';
COMMENT ON COLUMN setor.ativo IS 'Se o setor está em uso. Setor inativo não aparece para encaminhar nem no cadastro de pessoas. Requisitos: RF10.';
COMMENT ON COLUMN setor.criado_em IS 'Data e hora do cadastro do setor. Requisitos: RF10.';
COMMENT ON COLUMN setor.atualizado_em IS 'Data e hora da última alteração do setor. Requisitos: RF10.';
COMMENT ON TABLE usuario IS 'Pessoas com acesso ao sistema, cada uma em um setor e com um perfil. Quem aparece em alguma cadeia não é apagado, só desativado. Requisitos: RF01, RF11, RF16.';
COMMENT ON COLUMN usuario.id IS 'Identificador do usuário. Requisitos: RF01.';
COMMENT ON COLUMN usuario.nome IS 'Nome completo da pessoa; de 2 a 160 caracteres. Requisitos: RF01.';
COMMENT ON COLUMN usuario.matricula IS 'Matrícula funcional; única. Requisitos: RF01.';
COMMENT ON COLUMN usuario.email IS 'E-mail de acesso; único sem diferenciar maiúsculas. Requisitos: RF01.';
COMMENT ON COLUMN usuario.senha_hash IS 'Hash bcrypt ou Argon2id da senha; senha em texto puro é recusada. Requisitos: RF01, RNF-S4.';
COMMENT ON COLUMN usuario.perfil IS 'Perfil de acesso: perito, normal ou administrador. Requisitos: RF16.';
COMMENT ON COLUMN usuario.setor_id IS 'Setor ao qual a pessoa pertence. Requisitos: RF11.';
COMMENT ON COLUMN usuario.ativo IS 'Se a pessoa pode entrar no sistema. Requisitos: RF01.';
COMMENT ON COLUMN usuario.ultimo_login_em IS 'Data e hora do último login; vazio se nunca entrou. Requisitos: RF01.';
COMMENT ON COLUMN usuario.criado_em IS 'Data e hora do cadastro da pessoa. Requisitos: RF01.';
COMMENT ON COLUMN usuario.atualizado_em IS 'Data e hora da última alteração da pessoa. Requisitos: RF01.';
COMMENT ON TABLE token_revogado IS 'Identificadores de tokens de acesso (JWT) cancelados antes de vencer, por saída, desativação ou mudança de perfil ou setor. O token em si não fica no banco; a API recusa qualquer token cujo identificador esteja aqui. Requisitos: RF01, RNF02, RNF-S4.';
COMMENT ON COLUMN token_revogado.id_token IS 'Identificador do token JWT cancelado (campo "jti" do token). Requisitos: RF01, RNF02.';
COMMENT ON COLUMN token_revogado.usuario_id IS 'Pessoa dona do token. Requisitos: RF01.';
COMMENT ON COLUMN token_revogado.expira_em IS 'Quando o token venceria; depois disso a linha pode ser apagada. Requisitos: RNF02, RNF-S4.';
COMMENT ON COLUMN token_revogado.revogado_em IS 'Quando o token foi cancelado. Requisitos: RF01.';
COMMENT ON TABLE ocorrencia IS 'Dados do pop-up "Vincular ocorrência". Todos os campos são opcionais, mas a linha só existe com ao menos um preenchido. O código GIGANTE junta evidências da mesma ocorrência. Requisitos: RF02b (ocorrência), RF02c, RF02d, RF02e.';
COMMENT ON COLUMN ocorrencia.id IS 'Identificador da ocorrência. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.codigo_gigante IS 'Código GIGANTE/SSP; único quando preenchido; junta evidências da mesma ocorrência. Requisitos: RF02c, RF02d.';
COMMENT ON COLUMN ocorrencia.numero_oficio IS 'Número do ofício que pediu a perícia. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.delegacia_origem IS 'Delegacia que originou a ocorrência. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.tipo_crime IS 'Tipo de crime (lista fixa). Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.data_hora_ocorrencia IS 'Quando o fato aconteceu, informado por quem cadastra. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.endereco_ocorrencia IS 'Endereço onde o fato aconteceu. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.observacao IS 'Observações livres sobre a ocorrência. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.criado_por_id IS 'Pessoa que cadastrou a ocorrência. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.criado_em IS 'Data e hora do cadastro da ocorrência. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia.atualizado_em IS 'Data e hora da última alteração da ocorrência. Requisitos: RF02c.';
COMMENT ON TABLE ocorrencia_bo IS 'Boletins de ocorrência (B.O.) de cada ocorrência; uma ocorrência pode ter vários. A evidência chega aos B.O.s pela ocorrência. Requisitos: RF02b (ocorrência), RF02c.';
COMMENT ON COLUMN ocorrencia_bo.ocorrencia_id IS 'Ocorrência à qual o B.O. pertence. Requisitos: RF02b (ocorrência).';
COMMENT ON COLUMN ocorrencia_bo.numero_bo IS 'Número do boletim de ocorrência; não se repete na mesma ocorrência. Requisitos: RF02b (ocorrência), RF02c.';
COMMENT ON COLUMN ocorrencia_bo.adicionado_por_id IS 'Pessoa que incluiu o B.O. Requisitos: RF02c.';
COMMENT ON COLUMN ocorrencia_bo.adicionado_em IS 'Data e hora da inclusão do B.O. Requisitos: RF02c.';
COMMENT ON TABLE evidencia IS 'O objeto rastreado: identificação, foto e situação atual. As colunas de situação são uma cópia de leitura rápida; a fonte da verdade é a cadeia de custódia. Requisitos: RF02, RF03, RF12, RF13, RF14, RF17, RF18, RF19.';
COMMENT ON COLUMN evidencia.id IS 'Identificador interno da evidência. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.codigo IS 'Código da evidência, como EV-2026-0001; único; não muda depois do cadastro. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.tipo_evidencia IS 'Tipo da evidência (lista fixa). Requisitos: RF02.';
COMMENT ON COLUMN evidencia.descricao IS 'Descrição do objeto. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.endereco_coleta IS 'Endereço onde a evidência foi encontrada. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.latitude_coleta IS 'Latitude do local onde a evidência foi encontrada. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.longitude_coleta IS 'Longitude do local onde a evidência foi encontrada. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.ocorrencia_id IS 'Ocorrência vinculada; vazio se não houver. Requisitos: RF02b (ocorrência), RF02e.';
COMMENT ON COLUMN evidencia.foto_caminho_arquivo IS 'Onde o arquivo da foto foi guardado (pasta ou armazenamento em nuvem). Requisitos: RF02.';
COMMENT ON COLUMN evidencia.foto_nome_arquivo IS 'Nome original do arquivo enviado. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.foto_tipo_arquivo IS 'Formato da foto: image/jpeg, image/png, image/heic ou image/webp. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.foto_tamanho_bytes IS 'Tamanho do arquivo da foto, em bytes. Requisitos: RF02.';
COMMENT ON COLUMN evidencia.foto_hash_sha256 IS 'SHA-256 do arquivo da foto, calculado no servidor no momento do envio. Requisitos: RF03, RNF04.';
COMMENT ON COLUMN evidencia.coletado_por_id IS 'Pessoa que registrou a coleta. Requisitos: RF02, RF08c.';
COMMENT ON COLUMN evidencia.coletado_em IS 'Data e hora do cadastro da coleta (hora do servidor). Requisitos: RF02, RF08c.';
COMMENT ON COLUMN evidencia.situacao IS 'Situação atual da evidência (lista fixa). Requisitos: RF12c, RF13, RF13e, RF18, RF19.';
COMMENT ON COLUMN evidencia.setor_atual_id IS 'Setor onde a evidência está agora. Requisitos: RF14, RF17.';
COMMENT ON COLUMN evidencia.setor_destino_pendente_id IS 'Setor para onde foi encaminhada, enquanto está em trânsito. Requisitos: RF12, RF13, RF14.';
COMMENT ON COLUMN evidencia.destino_externo_nome IS 'Nome do destino fora do Instituto. Requisitos: RF13b.';
COMMENT ON COLUMN evidencia.destino_externo_endereco IS 'Endereço do destino fora do Instituto. Requisitos: RF13b.';
COMMENT ON COLUMN evidencia.perito_responsavel_id IS 'Perito que assumiu a análise; só ele conclui. Requisitos: RF17, RF18, RF19.';
COMMENT ON COLUMN evidencia.atualizado_em IS 'Data e hora da última mudança na evidência. Requisitos: RF12, RF14, RF18, RF19.';
COMMENT ON TABLE lote_lacre IS 'Lotes de lacres numerados do Instituto, gerados por um administrador antes de ir a campo. Só aceita inserção. Requisitos: RF04, RF06.';
COMMENT ON COLUMN lote_lacre.id IS 'Identificador interno do lote. Requisitos: RF04.';
COMMENT ON COLUMN lote_lacre.codigo_lote IS 'Código do lote, como L-2026-0001, gerado pelo banco. Requisitos: RF04.';
COMMENT ON COLUMN lote_lacre.quantidade IS 'Quantidade de lacres no lote, de 1 a 500. Requisitos: RF04.';
COMMENT ON COLUMN lote_lacre.primeiro_numero_lacre IS 'Número do primeiro lacre do lote. Requisitos: RF04, RF06.';
COMMENT ON COLUMN lote_lacre.ultimo_numero_lacre IS 'Número do último lacre do lote. Requisitos: RF04, RF06.';
COMMENT ON COLUMN lote_lacre.gerado_por_id IS 'Administrador que gerou o lote. Requisitos: RF04, RF16.';
COMMENT ON COLUMN lote_lacre.gerado_em IS 'Data e hora da geração do lote. Requisitos: RF04.';
COMMENT ON TABLE lacre IS 'Cada lacre físico: do Instituto (com lote e QR code) ou externo usado como lacre principal da evidência (sem lote). Segue o ciclo disponível, vinculado, rompido. Requisitos: RF04, RF04b, RF04c, RF04d, RF05, RF05b, RF05c, RF05d, RF05e, RF07, RF07b, RF07c, RNF05.';
COMMENT ON COLUMN lacre.id IS 'Identificador interno do lacre. Requisitos: RF04.';
COMMENT ON COLUMN lacre.numero_lacre IS 'Número impresso no lacre e único conteúdo do QR code. Requisitos: RF04c, RF05e, RNF05.';
COMMENT ON COLUMN lacre.emissor IS 'Quem emitiu o lacre (lista fixa). Requisitos: RF04d, RF05d, RF06b.';
COMMENT ON COLUMN lacre.lote_id IS 'Lote de origem do lacre. Requisitos: RF04, RF04d.';
COMMENT ON COLUMN lacre.situacao IS 'Situação do lacre: disponível, vinculado ou rompido. Requisitos: RF04b, RF05b, RF07.';
COMMENT ON COLUMN lacre.evidencia_id IS 'Evidência em que o lacre está ou esteve. Requisitos: RF05b, RF05c.';
COMMENT ON COLUMN lacre.hash_foto_na_associacao IS 'SHA-256 da foto da evidência no momento em que o lacre foi associado. Requisitos: RF05b.';
COMMENT ON COLUMN lacre.cadastrado_por_id IS 'Pessoa que cadastrou um lacre externo. Requisitos: RF05d.';
COMMENT ON COLUMN lacre.cadastrado_em IS 'Data e hora em que o lacre entrou no sistema. Requisitos: RF04, RF05d.';
COMMENT ON COLUMN lacre.vinculado_por_id IS 'Pessoa que associou o lacre à evidência. Requisitos: RF05, RF05b.';
COMMENT ON COLUMN lacre.vinculado_em IS 'Data e hora da associação do lacre. Requisitos: RF05b.';
COMMENT ON COLUMN lacre.rompido_por_id IS 'Pessoa que registrou o rompimento do lacre. Requisitos: RF07, RF07c.';
COMMENT ON COLUMN lacre.motivo_rompimento IS 'Motivo do rompimento do lacre. Requisitos: RF07.';
COMMENT ON COLUMN lacre.rompido_em IS 'Data e hora do rompimento. Requisitos: RF07.';
COMMENT ON TABLE lacre_referencia_externa IS 'Lacres de outras instituições que já estavam na evidência, ligados ao lacre do Instituto como registro histórico. Só aceita inserção. Requisitos: RF04e.';
COMMENT ON COLUMN lacre_referencia_externa.id IS 'Identificador da referência. Requisitos: RF04e.';
COMMENT ON COLUMN lacre_referencia_externa.lacre_id IS 'Lacre do Instituto ao qual a referência se liga. Requisitos: RF04e.';
COMMENT ON COLUMN lacre_referencia_externa.emissor IS 'Quem emitiu o lacre externo (qualquer emissor, menos o Instituto). Requisitos: RF04e.';
COMMENT ON COLUMN lacre_referencia_externa.numero_lacre_externo IS 'Número impresso no lacre da outra instituição. Requisitos: RF04e.';
COMMENT ON COLUMN lacre_referencia_externa.observacao IS 'Observação livre sobre o lacre externo. Requisitos: RF04e.';
COMMENT ON COLUMN lacre_referencia_externa.associado_por_id IS 'Pessoa que registrou a referência. Requisitos: RF04e.';
COMMENT ON COLUMN lacre_referencia_externa.associado_em IS 'Data e hora do registro da referência. Requisitos: RF04e.';
COMMENT ON TABLE cadeia_custodia IS 'Histórico de cada evidência, um registro por movimentação, encadeado por SHA-256. Só aceita inserção. Número de sequência, hashes e data e hora são preenchidos pelo banco. Requisitos: RF08, RF09, RF12, RF13, RF14, RF17, RF18, RF19, RF20, RNF03, RNF04.';
COMMENT ON COLUMN cadeia_custodia.id IS 'Identificador do registro; entra no cálculo do hash. Requisitos: RF08, RF09.';
COMMENT ON COLUMN cadeia_custodia.evidencia_id IS 'Evidência a que o registro pertence. Requisitos: RF08.';
COMMENT ON COLUMN cadeia_custodia.numero_sequencia IS 'Ordem do registro na cadeia: 1, 2, 3... sem buracos. Requisitos: RF08c, RF09.';
COMMENT ON COLUMN cadeia_custodia.acao IS 'O que aconteceu nesta movimentação (lista fixa). Requisitos: RF08, RF13g, RF18.';
COMMENT ON COLUMN cadeia_custodia.registrado_por_id IS 'Pessoa logada que fez o registro. Requisitos: RF08, RF14.';
COMMENT ON COLUMN cadeia_custodia.nome_responsavel_posse IS 'Quem está com a evidência nas mãos; pode ser alguém sem login. Requisitos: RF08, RF12b.';
COMMENT ON COLUMN cadeia_custodia.setor_atual_id IS 'Setor onde a ação aconteceu. Requisitos: RF14, RF17.';
COMMENT ON COLUMN cadeia_custodia.setor_destino_id IS 'Setor de destino do encaminhamento ou do armazenamento. Requisitos: RF08b, RF12.';
COMMENT ON COLUMN cadeia_custodia.destino_externo_nome IS 'Nome do destino fora do Instituto. Requisitos: RF13b.';
COMMENT ON COLUMN cadeia_custodia.destino_externo_endereco IS 'Endereço do destino fora do Instituto. Requisitos: RF13b.';
COMMENT ON COLUMN cadeia_custodia.endereco_local IS 'Endereço em texto onde a ação aconteceu. Requisitos: RF08c, RF13c.';
COMMENT ON COLUMN cadeia_custodia.lacre_id IS 'Lacre envolvido no evento de lacre. Requisitos: RF05, RF07.';
COMMENT ON COLUMN cadeia_custodia.data_hora_registro IS 'Data e hora do registro, sempre do servidor. Requisitos: RF08, RNF-S1.';
COMMENT ON COLUMN cadeia_custodia.observacao IS 'Observação livre sobre a movimentação. Requisitos: RF08.';
COMMENT ON COLUMN cadeia_custodia.gps_obtido IS 'Se o aparelho informou a localização no momento do registro. Requisitos: RF02b (local), RF13c, RF13f.';
COMMENT ON COLUMN cadeia_custodia.gps_latitude IS 'Latitude do aparelho no momento do registro. Requisitos: RF02b (local), RF13f.';
COMMENT ON COLUMN cadeia_custodia.gps_longitude IS 'Longitude do aparelho no momento do registro. Requisitos: RF02b (local), RF13f.';
COMMENT ON COLUMN cadeia_custodia.gps_precisao_metros IS 'Precisão da localização informada pelo navegador, em metros. Requisitos: RF13f.';
COMMENT ON COLUMN cadeia_custodia.cadastro_fora_do_local IS 'Só na coleta: se o cadastro foi feito longe do endereço informado. Requisitos: RF02b (local).';
COMMENT ON COLUMN cadeia_custodia.justificativa_fora_local IS 'Justificativa de o cadastro ter sido feito fora do local. Requisitos: RF02b (local).';
COMMENT ON COLUMN cadeia_custodia.hash_registro_anterior IS 'Hash do registro anterior desta evidência; 64 zeros no primeiro. Requisitos: RF09.';
COMMENT ON COLUMN cadeia_custodia.hash_registro IS 'SHA-256 deste registro, calculado pelo banco. Requisitos: RF09, RNF04.';
COMMENT ON TABLE verificacao_integridade IS 'Resultado de cada verificação de integridade pedida na tela. Só aceita inserção. Requisitos: RF21, RF22, RF23.';
COMMENT ON COLUMN verificacao_integridade.id IS 'Identificador da verificação. Requisitos: RF21.';
COMMENT ON COLUMN verificacao_integridade.evidencia_id IS 'Evidência verificada. Requisitos: RF21.';
COMMENT ON COLUMN verificacao_integridade.executada_por_id IS 'Pessoa que pediu a verificação. Requisitos: RF21.';
COMMENT ON COLUMN verificacao_integridade.executada_em IS 'Data e hora da verificação. Requisitos: RF21, RF23.';
COMMENT ON COLUMN verificacao_integridade.total_registros IS 'Quantos registros da cadeia foram conferidos. Requisitos: RF21.';
COMMENT ON COLUMN verificacao_integridade.registros_divergentes IS 'Quantos registros não conferiram. Requisitos: RF22.';
COMMENT ON COLUMN verificacao_integridade.cadeia_integra IS 'Verdadeiro quando nenhum registro diverge; calculado pelo banco. Requisitos: RF21, RF23.';
COMMENT ON COLUMN verificacao_integridade.hash_ultimo_registro IS 'Hash do último registro no momento da verificação. Requisitos: RF23.';
COMMENT ON TABLE verificacao_divergencia IS 'Uma linha para cada problema encontrado em uma verificação. Só aceita inserção. Requisitos: RF22.';
COMMENT ON COLUMN verificacao_divergencia.verificacao_id IS 'Verificação em que a divergência apareceu. Requisitos: RF22.';
COMMENT ON COLUMN verificacao_divergencia.numero_sequencia IS 'Número do registro que não conferiu. Requisitos: RF22.';
COMMENT ON COLUMN verificacao_divergencia.cadeia_custodia_id IS 'Registro da cadeia que não conferiu. Requisitos: RF22.';
COMMENT ON COLUMN verificacao_divergencia.tipo_divergencia IS 'Tipo do problema encontrado (lista fixa). Requisitos: RF22.';
COMMENT ON COLUMN verificacao_divergencia.hash_armazenado IS 'Hash que estava guardado no registro. Requisitos: RF22.';
COMMENT ON COLUMN verificacao_divergencia.hash_recalculado IS 'Hash que deveria estar no registro. Requisitos: RF22.';
COMMENT ON TABLE log_acesso IS 'Quem consultou ou exportou cada evidência, para auditoria e LGPD. Opcional no MVP. Só aceita inserção. Requisitos: RNF-S7.';
COMMENT ON COLUMN log_acesso.id IS 'Número sequencial do acesso, gerado pelo banco. Requisitos: RNF-S7.';
COMMENT ON COLUMN log_acesso.usuario_id IS 'Pessoa que acessou. Requisitos: RNF-S7.';
COMMENT ON COLUMN log_acesso.evidencia_id IS 'Evidência consultada ou exportada. Requisitos: RNF-S7.';
COMMENT ON COLUMN log_acesso.acao_acesso IS 'O que a pessoa fez (lista fixa). Requisitos: RNF-S7, RF23.';
COMMENT ON COLUMN log_acesso.endereco_ip IS 'Endereço IP de quem acessou. Requisitos: RNF-S7.';
COMMENT ON COLUMN log_acesso.navegador IS 'Identificação do navegador (user agent). Requisitos: RNF-S7.';
COMMENT ON COLUMN log_acesso.ocorrido_em IS 'Data e hora do acesso. Requisitos: RNF-S7.';

COMMIT;
