# CETESB – Credenciais (Frontend + Supabase)

**Objetivo**  
Plataforma para cadastro e verificação pública de credenciais de agentes da CETESB.
- **Pública (sem login)**: `public.html?reg=000001` (QR Code aponta para essa rota)
- **Restrita (login)**: `index.html` (redireciona para `admin.html` ou `consulta.html` conforme o perfil)

## Arquitetura
- **Frontend estático**: GitHub Pages (este repositório)
- **Backend**: Supabase (PostgreSQL + Auth + Storage + Row Level Security - RLS)
- **Segurança**: RLS no banco – leitura pública mínima; escrita somente para admin (nível 2)

## Estrutura de pastas/arquivos
```
/index.html       # Login (Supabase Auth)
admin.html        # Cadastro/edição (admin nível 2)
consulta.html     # Consulta (gerente nível 1 e admin nível 2)
public.html       # Página pública do QR (?reg=000000)
config.html       # Importar/exportar CSV (apenas admin)
style.css         # Estilos
config.json       # Configurações (URLs, chaves públicas)
/media/           # Imagens (cetesb-logo.png, bg-cetesb.jpg)
README.md
```

## Configuração (GitHub Pages)
1. **Settings → Pages**: Source = `Deploy from a branch` → Branch = `main` → Folder = `/ (root)`.
2. URL final: `https://USUARIO.github.io/credenciais`
3. Edite `config.json`:
```json
{
  "BASE_URL": "https://USUARIO.github.io/credenciais",
  "supabaseUrl": "https://<SEU-PROJETO>.supabase.co",
  "supabaseAnonKey": "<ANON_PUBLIC_KEY>"
}
```

## Banco de Dados (Supabase)
**Tabelas (schema `public`):**

### `credenciais`
- `cred_cod` (int2, **PK/UNIQUE**)
- `descricao` (text)
- **RLS**: `SELECT` público `using (true)`
- Dados (5 linhas):
  1 = Fiscalização e Licenciamento de Fontes de Poluição, Recursos Naturais e Áreas Ambientalmente Protegidas  
  2 = Apoio à Fiscalização e Licenciamento de Fontes de Poluição, Recursos Naturais e Áreas Ambientalmente Protegidas  
  3 = Amostragem de Fontes de Poluição  
  4 = Fiscalização de Fontes Móveis  
  5 = Auditoria Técnica

### `unidades`
- `sigla` (text, **PK/UNIQUE**)
- `nome_da_unidade` (text)
- `centro_de_custo` (text)
- **RLS**: `SELECT` público `using (true)`
- Usada para **auto-preenchimento** e filtros.

### `empregados`
- `registro` (char(6) ou text, **PK**)
- `cred_num` (text)
- `cred_cod` (int2, **FK** → `credenciais.cred_cod`)
- `status` (text) – valores: **"Ativo"** | **"Em andamento"**
- `nome` (text), `cargo` (text)
- `sigla` (text), `nome_da_unidade` (text), `centro_de_custo` (text)
- `validade` (date) – **data final** (única data)
- `doe` (text, opcional)
- `foto_path` (text) – caminho no Storage (ex.: `fotos/000001.jpg`)
- `ultima_atualizacao` (timestamptz, default `now()`) *(opcional)*
- **RLS**:
  - `SELECT` público `using (true)` (necessário para a página pública/QR)
  - `ALL` somente admin:
    ```sql
    using (auth.uid() in (select user_id from public.usuarios_app where nivel = 2))
    with check (auth.uid() in (select user_id from public.usuarios_app where nivel = 2))
    ```

### `usuarios_app`
- `user_id` (uuid, **PK**, FK → `auth.users.id`)
- `matricula` (text, UNIQUE, 6 dígitos)
- `nivel` (int2; 0=nenhum, 1=gerente, 2=admin)
- `root_sigla` (text; p/ gerente define prefixo de siglas, ex.: `AR`)
- `pwd_is_default` (bool, default true) *(opcional)*
- **RLS**:
  - self-read: `using (auth.uid() = user_id)`
  - admin-read: `using (auth.uid() in (select user_id from public.usuarios_app where nivel = 2))`
  - admin-write: `for ALL` com `using/with check` iguais ao admin-read

**Storage:**
- Bucket **`fotos`** → **Public ON** (GET sem login)
- Policies: leitura pública; upload/update/delete somente autenticado (ou só admin)
- Nome do arquivo de foto = `REGISTRO.ext` (PNG/JPG)

## Regras de Status (página pública)
- **ATIVO**: `status = "Ativo"` **e** `validade >= hoje`.
- **INATIVO**: qualquer outro caso (inclui "Em andamento" e/ou validade vencida).

## Fluxos principais
- **QR Code**: gerado no `admin.html` (botão **Gerar QR**) → URL:  
  `BASE_URL/public.html?reg=000000`
- **Cadastro** (admin): cria/edita/exclui, upload de fotos (bucket).
- **Consulta** (gerente): vê registros cuja `sigla` **começa com** `root_sigla`.
- **Importar/Exportar CSV** (admin): `config.html`
  - `empregados.csv` cabeçalhos:  
    `registro,cred_num,cred_cod,status,nome,cargo,sigla,nome_da_unidade,centro_de_custo,validade,doe,foto_path`
  - `unidades.csv` cabeçalhos:  
    `sigla,nome_da_unidade,centro_de_custo`
  - Upsert por `registro` (empregados) e `sigla` (unidades)

## Procedimento de Acesso
1. ARAS (admin) convida e-mails via **Supabase → Authentication → Users**.
2. Em `usuarios_app`, ARAS cria/atualiza linhas com: `user_id`, `matricula`, `nivel` (1 ou 2), `root_sigla` (para gerente).
3. Login em `index.html`; roteamento:
   - **nível 2** → `admin.html`
   - **nível 1** → `consulta.html`

## Segurança
- `config.json` usa **Anon Public Key** (apenas leitura, controlada por RLS).
- Escrita (INSERT/UPDATE/DELETE) somente para **admin nível 2** autenticado.
- Página pública lê dados mínimos.

## Migração para Produção (TI)
- Publicar os mesmos arquivos no servidor da CETESB.
- Ajustar `config.json` com o **BASE_URL** de produção e (se necessário) chaves/URL do projeto Supabase de produção.
- Verificar CORS e policies do Storage.

## Troubleshooting
- **“Registro não encontrado”**: confirmar `registro` (6 dígitos), existência em `empregados` e policies de `SELECT`.
- **Foto não aparece**: checar `foto_path` e se o bucket `fotos` está público.
- **Sem permissão para editar**: conferir `usuarios_app.nivel = 2`.
- **Import CSV falha**: conferir cabeçalhos e `YYYY-MM-DD` em `validade`.


-------

# CETESB – Plataforma de Credenciais (Banco PostgreSQL + Back-end REST + Front-end estático)
**Versão:** 2.0 • **Data:** 03/10/2025**

**Finalidade institucional** — Este manual destina-se à TI da CETESB para **construir**, em ambiente próprio da CETESB, o **banco de dados PostgreSQL**, o **back-end HTTP (API REST)** e o **front-end estático** da **plataforma de credenciamento de agentes** e **acesso público ao status por QR code no crachá funcional**, solução que substitui o cartão avulso de credencial.  
Trata-se da implantação do sistema cuja **demonstração funcional** roda hoje no Supabase (PostgreSQL gerenciado) e em GitHub Pages. A demonstração foi concebida pela **equipe do setor ARAS (Setor de Dados Corporativos, Relações Trabalhistas e Sindicais)**, sob coordenação da **divisão ARA (Divisão de Gestão de Pessoas, Benefícios e Relações Trabalhistas)** e do **departamento AR (Departamento de Gestão de Pessoas)**.  
O código front-end de referência encontra-se em: **https://github.com/fabioeidiara/credenciais** (repositório do piloto).

> **Objetivo técnico** — Trata-se de guia, em **linguagem didática**, para que a equipe de TI da companhia monte **o stack** (banco de dados, API e site) **sem necessidade de consulta fora do manual**. O manual descreve **todas as tabelas e colunas**, as **regras de negócio**, as **rotas da API**, o **esqueleto do back-end** (arquivo por arquivo) e como **disponibilizar no site público da CETESB**.

---

## SUMÁRIO
1. [Arquitetura alvo](#1-arquitetura-alvo)  
2. [Banco PostgreSQL (modelo, DDL e dicionário de dados)](#2-banco-postgresql-modelo-ddl-e-dicionário-de-dados)  
3. [Importação/Exportação (CSV) e cargas iniciais](#3-importaçãoexportação-csv-e-cargas-iniciais)  
4. [Armazenamento de fotos](#4-armazenamento-de-fotos)  
5. [Back-end REST (Node.js + Express) — esqueleto completo](#5-back-end-rest-nodejs--express--esqueleto-completo)  
6. [Contrato da API (endpoints, filtros, exemplos)](#6-contrato-da-api-endpoints-filtros-exemplos)  
7. [Front-end estático (HTML/CSS/JS) — estrutura e integração](#7-front-end-estático-htmlcssjs--estrutura-e-integração)  
8. [Segurança (DB, API, Web) e conformidade](#8-segurança-db-api-web-e-conformidade)  
9. [Deploy no site público da CETESB (NGINX + systemd)](#9-deploy-no-site-público-da-cetesb-nginx--systemd)  
10. [Plano de testes e validações](#10-plano-de-testes-e-validações)  
11. [Operação, logs, backups e restauração](#11-operação-logs-backups-e-restauração)  
12. [Apêndices (OpenAPI, NGINX, scripts utilitários)](#12-apêndices-openapi-nginx-scripts-utilitários)

---

## 1) ARQUITETURA ALVO

**Camadas**  
- **Front-end**: HTML/CSS/JS estático (sem framework), responsivo e otimizado para celular na página pública (QR Code).  
- **Back-end (API REST)**: Node.js (Express), validação, autorização por perfil (administrativo ou de gerente de unidade), upload de fotos e CRUD (criar, ler, atualizar e excluir).  
- **Banco de dados**: PostgreSQL (gerenciado pela CETESB).  
- **Fotos**: pasta estática no servidor web (ou objeto S3/MinIO). O banco guarda apenas `foto_path` (ex.: `000001.jpg`).

**Fluxo QR Code**  
1. Crachá possui QR Code `https://<site>/public.html?reg=000001`.  
2. `public.html` chama `GET /api/empregados/000001`.  
3. API consulta o banco e retorna JSON; a página renderiza o cartão com **status derivado** pela validade.  
4. A foto é obtida em `https://<site>/fotos/000001.jpg` (ou via endpoint da API).

**Perfis**  
- **Administrador (ARAS)**: CRUD completo e importa/exporta CSV.  
- **Gerente de unidade**: acesso de consulta **limitado ao seu escopo (por siglas)** (unidade-base + subordinadas).  
- **Público**: somente `public.html` por QR Code.

---

## 2) BANCO POSTGRESQL (MODELO, DDL E DICIONÁRIO DE DADOS)

### 2.1 Modelo lógico
Tabelas:
- `credenciais` — catálogo dos códigos de 1 a 5 e descrição.  
- `unidades` — catálogo de siglas e nome de unidade.  
- `empregados` — cadastro de agentes credenciados.  
- `usuarios_app` — mapeia usuário autenticado a nível (0/1/2) e a sigla-base.

### 2.2 Dicionário de dados (resumo)

**`credenciais`**
- `cred_cod` (smallint, PK): de 1 a 5. 
- `descricao` (text, not null).

**`unidades`**
- `sigla` (text, PK): de 1 a 4 letras.  
- `nome_da_unidade` (text, not null).  
- `centro_custo` (text, opcional).

**`empregados`**
- `registro` (text, PK): **6 dígitos** com zeros (ex.: `000001`).  
- `cred_num` (text, not null): **4 dígitos** (ex.: `1234`).  
- `cred_cod` (smallint, not null, FK→`credenciais`).  
- `status` (text, not null, default `Ativo`, check in `('Ativo','Em andamento','Inativo')`).  
- `nome` (text, not null).  
- `sigla` (text, not null, FK→`unidades`).  
- `nome_da_unidade` (text, not null, default `''`) — cópia do nome no momento do cadastro (historicidade).  
- `validade` (date, not null) — **não há data de início**.  
- `doe` (text, opcional) — `Nº/ano`.  
- `foto_path` (text, opcional) — ex.: `000001.jpg`.  
- `updated_at` (timestamptz, default now()) — auditoria.

**`usuarios_app`**
- `user_id` (uuid, PK) — identidade do provedor (SSO/sistema).  
- `matricula` (text, unique) — 6 dígitos (login).  
- `nivel` (smallint, default 0) — 0=nenhum; **1=gerente**; **2=administrativo**.  
- `sigla` (text, opcional) — base de escopo para gerente.  
- `ativo` (boolean, default true).  
- `updated_at` (timestamptz, default now()).  
- `provedor` (text, default `cetesb`).

### 2.3 DDL (criar do zero)

```sql
-- Criar database (como superuser) — ajustar nome/owner
-- create database credenciais with encoding 'UTF8';

-- Conectar e criar objetos (psql: \c credenciais)

-- 1) Catálogo de credenciais
create table if not exists public.credenciais (
  cred_cod     smallint primary key,
  descricao    text not null
);

-- 2) Catálogo de unidades
create table if not exists public.unidades (
  sigla            text primary key,
  nome_da_unidade  text not null,
  centro_custo     text
);

-- 3) Cadastro de empregados
create table if not exists public.empregados (
  registro         text primary key,
  cred_num         text not null,
  cred_cod         smallint not null references public.credenciais(cred_cod) on update cascade on delete restrict,
  status           text not null check (status in ('Ativo','Em andamento','Inativo')) default 'Ativo',
  nome             text not null,
  sigla            text not null references public.unidades(sigla) on update cascade on delete restrict,
  nome_da_unidade  text not null default '',
  validade         date not null,
  doe              text,
  foto_path        text,
  updated_at       timestamptz not null default now()
);

-- Índices úteis
create index if not exists empregados_sigla_idx    on public.empregados(sigla);
create index if not exists empregados_status_idx   on public.empregados(status);
create index if not exists empregados_validade_idx on public.empregados(validade);

-- 4) Usuários do app (autorização de perfis)
create table if not exists public.usuarios_app (
  user_id     uuid primary key,
  matricula   text not null unique,
  nivel       smallint not null default 0,
  sigla       text,
  ativo       boolean not null default true,
  updated_at  timestamptz not null default now(),
  provedor    text not null default 'cetesb'
);

-- Trigger de auditoria (updated_at)
create or replace function touch_updated_at() returns trigger as $$
begin
  new.updated_at := now();
  return new;
end; $$ language plpgsql;

drop trigger if exists trg_empregados_touch on public.empregados;
create trigger trg_empregados_touch
before update on public.empregados
for each row execute function touch_updated_at();
```

### 2.4 View pública (opcional, recomendada)

```sql
create or replace view public.v_cred_publica as
select
  e.registro,
  e.cred_num,
  e.cred_cod,
  c.descricao as cred_descricao,
  e.nome,
  e.sigla,
  e.nome_da_unidade,
  e.validade,
  e.status,
  e.foto_path
from public.empregados e
join public.credenciais c on c.cred_cod = e.cred_cod;
```

> A `public.html` pode consultar a view; é mais segura e estável se, no futuro, a tabela ganhar novas colunas internas.

---

## 3) IMPORTAÇÃO/EXPORTAÇÃO (CSV) E CARGAS INICIAIS

### 3.1 Carga de catálogos (seed)

```sql
insert into public.credenciais (cred_cod, descricao) values
(1,'Fiscalização e Licenciamento de Fontes de Poluição, Recursos Naturais e Áreas Ambientalmente Protegidas'),
(2,'Apoio à Fiscalização e Licenciamento de Fontes de Poluição, Recursos Naturais e Áreas Ambientalmente Protegidas'),
(3,'Amostragem de Fontes de Poluição'),
(4,'Fiscalização de Fontes Móveis'),
(5,'Auditoria Técnica')
on conflict (cred_cod) do nothing;
```

`unidades.csv` (exemplo):
```csv
sigla,nome_da_unidade,centro_custo
AR,Diretoria AR,CC-AR
ARA,Departamento ARA,CC-ARA
ARAS,Setor de Administração do Departamento ARA,CC-ARAS
CLS,Agência Ambiental CLS,CC-CLS
```

Importar via psql:
```bash
psql "<conn>" -c "\copy public.unidades from 'unidades.csv' csv header"
```

### 3.2 Exportação (backup plano B)
```bash
psql "<conn>" -c "\copy (select * from public.empregados order by registro) to 'empregados-YYYYMMDD.csv' csv header"
```

---

## 4) ARMAZENAMENTO DE FOTOS

- **Diretório estático** no servidor web: `/var/www/credenciais/fotos/`  
- **Nome do arquivo** = `<registro>.<ext>` (ex.: `000001.jpg`).  
- **URL pública** = `https://<site>/fotos/000001.jpg`.  
- **Banco** guarda apenas `foto_path` (ex.: `000001.jpg`).  
- **Permissão de escrita**: o **serviço da API** (usuário do processo) precisa gravar nesta pasta.

> Alternativas: S3/MinIO com CDN; manter a mesma lógica (DB armazena `foto_path`).

---

## 5) BACK-END REST (Node.js + Express) — ESQUELETO COMPLETO

**Stack sugerido**  
- Node.js LTS (≥ 20)  
- Express, pg (Pool), cors, helmet, compression, express-rate-limit, multer (upload), sharp (processar imagem), zod (validação), jsonwebtoken (opcional), bcryptjs (opcional).  
- Logger: morgan/winston.

### 5.1 Estrutura de pastas

```
backend/
├─ package.json
├─ .env                 # variáveis de ambiente
├─ README.md
└─ src/
   ├─ index.js          # bootstrap
   ├─ app.js            # Express app
   ├─ config.js
   ├─ db.js             # pool do Postgres
   ├─ middleware/
   │  ├─ auth.js        # valida perfis (admin/gerente)
   │  ├─ cors.js
   │  ├─ errors.js
   │  └─ rateLimit.js
   ├─ routes/
   │  ├─ auth.js
   │  ├─ credenciais.js
   │  ├─ empregados.js
   │  ├─ unidades.js
   │  └─ upload.js
   ├─ services/
   │  └─ empregadosService.js
   ├─ validators/
   │  ├─ common.js
   │  └─ empregados.js
   └─ utils/
      └─ logger.js
```

### 5.2 `package.json`

```json
{
  "name": "cetesb-credenciais-api",
  "version": "1.0.0",
  "type": "module",
  "main": "src/index.js",
  "scripts": {
    "dev": "node --watch src/index.js",
    "start": "node src/index.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "compression": "^1.7.4",
    "cors": "^2.8.5",
    "express": "^4.19.2",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.0.0",
    "jsonwebtoken": "^9.0.2",
    "morgan": "^1.10.0",
    "multer": "^1.4.5-lts.1",
    "pg": "^8.11.5",
    "sharp": "^0.33.3",
    "zod": "^3.23.8"
  }
}
```

### 5.3 `.env` (exemplo)

```
NODE_ENV=production
PORT=8080

PGHOST=127.0.0.1
PGPORT=5432
PGDATABASE=credenciais
PGUSER=api_backend
PGPASSWORD=Trocar#Imediatamente

# JWT (se usar token no admin)
JWT_SECRET=trocar-por-valor-forte

# CORS
CORS_ORIGIN=https://site.cetesb.sp.gov.br

# Pasta das fotos (deve existir e ter permissão de escrita do serviço)
FOTOS_DIR=/var/www/credenciais/fotos
```

### 5.4 `src/config.js`

```js
import 'dotenv/config.js';

export const cfg = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '8080', 10),
  pg: {
    host: process.env.PGHOST,
    port: parseInt(process.env.PGPORT || '5432', 10),
    database: process.env.PGDATABASE,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    ssl: false
  },
  corsOrigin: (process.env.CORS_ORIGIN || '').split(',').map(s=>s.trim()).filter(Boolean),
  jwtSecret: process.env.JWT_SECRET || 'dev-secret',
  fotosDir: process.env.FOTOS_DIR || '/var/www/credenciais/fotos'
};
```

### 5.5 `src/db.js` (pool e helpers)

```js
import { Pool } from 'pg';
import { cfg } from './config.js';

export const pool = new Pool(cfg.pg);

export async function query(q, params){
  const client = await pool.connect();
  try {
    const res = await client.query(q, params);
    return res;
  } finally {
    client.release();
  }
}
```

### 5.6 `src/middleware/cors.js`

```js
import cors from 'cors';
import { cfg } from '../config.js';

export const corsMw = cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // permitir ferramentas locais
    if (cfg.corsOrigin.length === 0) return cb(null, true);
    if (cfg.corsOrigin.includes(origin)) return cb(null, true);
    return cb(new Error('CORS blocked'), false);
  },
  credentials: false,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
});
```

### 5.7 `src/middleware/errors.js`

```js
export function notFound(req,res,next){
  res.status(404).json({ error: 'not_found' });
}

export function errorHandler(err, req, res, next){
  console.error(err);
  if (res.headersSent) return;
  const code = err.status || 500;
  res.status(code).json({ error: err.code || 'server_error', message: err.message || 'Unexpected error' });
}
```

### 5.8 `src/middleware/rateLimit.js`

```js
import rateLimit from 'express-rate-limit';

export const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120, // 120 req/min por IP para endpoints públicos
});

export const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60, // mais restrito em gravações
});
```

### 5.9 `src/middleware/auth.js` (perfis e escopo)

> **Observação:** na CETESB, recomenda-se SSO (Azure AD). O esqueleto abaixo usa **JWT** simples emitido no `/auth/login` para fins de implantação rápida.

```js
import jwt from 'jsonwebtoken';
import { cfg } from '../config.js';
import { query } from '../db.js';

export function requireAuth(req,res,next){
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if(!token) return res.status(401).json({ error: 'unauthorized' });
  try{
    const payload = jwt.verify(token, cfg.jwtSecret);
    req.user = payload;
    return next();
  }catch(e){
    return res.status(401).json({ error: 'invalid_token' });
  }
}

export function requireAdmin(req,res,next){
  if(!req.user) return res.status(401).json({ error: 'unauthorized' });
  if(req.user.nivel !== 2) return res.status(403).json({ error: 'forbidden' });
  next();
}

export function requireGerenteOuAdmin(req,res,next){
  if(!req.user) return res.status(401).json({ error: 'unauthorized' });
  if(req.user.nivel === 2 || req.user.nivel === 1) return next();
  return res.status(403).json({ error: 'forbidden' });
}

// Helper para escopo de gerente (sigla-base + subordinadas, regra por prefixo)
export async function escopoSiglas(req){
  if (req.user?.nivel === 2) return null; // admin: sem restrição
  if (req.user?.nivel !== 1) return [];   // nenhum: vazio
  const base = (req.user.sigla || '').toUpperCase();
  if (!base) return [];
  // Regra hierárquica: A ⊃ AA ⊃ AAA ⊃ AAAA (prefix match)
  return [base]; // controle de prefixo será aplicado via SQL (sigla like 'AR%' etc), vide services
}
```

### 5.10 `src/validators/common.js` e `src/validators/empregados.js`

```js
// validators/common.js
import { z } from 'zod';

export const registro6 = z.string().regex(/^[0-9]{6}$/, 'registro deve ter 6 dígitos');
export const credNum4  = z.string().regex(/^[0-9]{4}$/, 'cred_num deve ter 4 dígitos');
export const credCod   = z.number().int().min(1).max(5);
export const statusStr = z.enum(['Ativo','Em andamento','Inativo']);
export const siglaStr  = z.string().regex(/^[A-Z]{1,4}$/, 'sigla inválida');
export const isoDate   = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'data no formato YYYY-MM-DD');
```

```js
// validators/empregados.js
import { z } from 'zod';
import { registro6, credNum4, credCod, statusStr, siglaStr, isoDate } from './common.js';

export const empregadoCreate = z.object({
  registro: registro6,
  cred_num: credNum4,
  cred_cod: credCod,
  status: statusStr,
  nome: z.string().min(1),
  sigla: siglaStr,
  nome_da_unidade: z.string().optional().default(''),
  validade: isoDate,
  doe: z.string().optional().nullable()
});

export const empregadoUpdate = empregadoCreate.partial().extend({
  registro: registro6 // obrigatório na rota com :registro
});
```

### 5.11 `src/services/empregadosService.js` (SQL parametrizado)

```js
import { query } from '../db.js';

export async function getEmpregadoByRegistro(registro){
  const sql = `select e.registro,e.cred_num,e.cred_cod,c.descricao as cred_descricao,
                      e.nome,e.sigla,e.nome_da_unidade,e.validade,e.status,e.foto_path
               from public.empregados e
               join public.credenciais c on c.cred_cod=e.cred_cod
               where e.registro=$1`;
  const r = await query(sql, [registro]);
  return r.rows[0] || null;
}

export async function listEmpregados({ q, sigla, status, limit=100, offset=0, prefixScope=null }){
  // prefixScope: string tipo 'AR' para gerente (sigla LIKE 'AR%')
  const conds = [];
  const params = [];
  let i = 1;

  if (q){
    conds.push(`(unaccent(e.nome) ilike unaccent($${i}) or e.registro ilike $${i})`);
    params.push(`%${q}%`);
    i++;
  }
  if (sigla){
    conds.push(`e.sigla = $${i}`);
    params.push(sigla);
    i++;
  }
  if (status){
    conds.push(`e.status = $${i}`);
    params.push(status);
    i++;
  }
  if (prefixScope){ // gerente
    conds.push(`e.sigla ilike $${i}`);
    params.push(`${prefixScope}%`);
    i++;
  }

  const where = conds.length ? `where ${conds.join(' and ')}` : '';
  const sql = `select e.registro,e.nome,e.sigla,e.validade,e.status
               from public.empregados e
               ${where}
               order by e.registro asc
               limit ${Math.min(+limit||100, 500)} offset ${+offset||0}`;

  const r = await query(sql, params);
  return r.rows;
}

export async function upsertEmpregado(obj){
  const sql = `insert into public.empregados
      (registro,cred_num,cred_cod,status,nome,sigla,nome_da_unidade,validade,doe,foto_path)
      values ($1,$2,$3,$4,$5,$6,coalesce($7,''),$8,$9,coalesce($10,foto_path))
      on conflict (registro) do update set
        cred_num=excluded.cred_num,
        cred_cod=excluded.cred_cod,
        status=excluded.status,
        nome=excluded.nome,
        sigla=excluded.sigla,
        nome_da_unidade=excluded.nome_da_unidade,
        validade=excluded.validade,
        doe=excluded.doe,
        updated_at=now()`;
  const params = [
    obj.registro, obj.cred_num, obj.cred_cod, obj.status, obj.nome, obj.sigla,
    obj.nome_da_unidade || '', obj.validade, obj.doe || null, obj.foto_path || null
  ];
  await query(sql, params);
  return obj.registro;
}

export async function deleteEmpregado(registro){
  await query('delete from public.empregados where registro=$1', [registro]);
}
```

### 5.12 Rotas

#### `src/routes/auth.js` (login simples por matrícula/senha — opcional)
> **Observação:** se houver SSO, remova este módulo e utilize o cabeçalho fornecido pelo proxy (ex.: `X-User-Id`).

```js
import { Router } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { cfg } from '../config.js';
import { query } from '../db.js';

export const auth = Router();

auth.post('/login', async (req,res) => {
  const { matricula, password } = req.body || {};
  if(!/^[0-9]{6}$/.test(matricula||'')) return res.status(400).json({ error:'invalid_matricula' });
  if(!password) return res.status(400).json({ error:'invalid_password' });

  // Exemplo: tabela com hash (se optar por senhas locais).
  // Caso use SSO, substituir por validação de header/token corporativo.
  const r = await query('select user_id, nivel, sigla, ativo from public.usuarios_app where matricula=$1', [matricula]);
  const u = r.rows[0];
  if(!u || !u.ativo) return res.status(401).json({ error:'unauthorized' });

  // Em ambiente sem senha local, pode aceitar "password == 'cetesb'" apenas para piloto.
  if (password !== 'cetesb') { // trocar por verificação de hash se necessário
    return res.status(401).json({ error: 'unauthorized' });
  }

  const token = jwt.sign({ sub:u.user_id, matricula, nivel:u.nivel, sigla:u.sigla||null }, cfg.jwtSecret, { expiresIn:'8h' });
  res.json({ token, nivel:u.nivel, sigla:u.sigla });
});
```

#### `src/routes/credenciais.js`

```js
import { Router } from 'express';
import { query } from '../db.js';
export const credenciais = Router();

credenciais.get('/', async (req,res,next)=>{
  try{
    const r = await query('select cred_cod, descricao from public.credenciais order by cred_cod');
    res.json(r.rows);
  }catch(e){ next(e); }
});
```

#### `src/routes/unidades.js`

```js
import { Router } from 'express';
import { query } from '../db.js';
export const unidades = Router();

unidades.get('/', async (req,res,next)=>{
  try{
    const r = await query('select sigla, nome_da_unidade from public.unidades order by sigla');
    res.json(r.rows);
  }catch(e){ next(e); }
});
```

#### `src/routes/empregados.js`

```js
import { Router } from 'express';
import { requireAuth, requireAdmin, requireGerenteOuAdmin, escopoSiglas } from '../middleware/auth.js';
import { publicLimiter, adminLimiter } from '../middleware/rateLimit.js';
import { empregadoCreate, empregadoUpdate } from '../validators/empregados.js';
import * as svc from '../services/empregadosService.js';

export const empregados = Router();

// Público (QR) — sem token
empregados.get('/:registro', publicLimiter, async (req,res,next)=>{
  try{
    const reg = req.params.registro;
    const row = await svc.getEmpregadoByRegistro(reg);
    if(!row) return res.status(404).json({ error:'not_found' });
    res.json(row);
  }catch(e){ next(e); }
});

// Lista filtrada (gerente/admin)
empregados.get('/', requireAuth, publicLimiter, async (req,res,next)=>{
  try{
    const { q, sigla, status, limit, offset } = req.query;
    const scope = await escopoSiglas(req); // null (admin) | [] | ['AR']
    const prefix = (scope && scope[0]) || null;
    const rows = await svc.listEmpregados({
      q: q?.toString()||null,
      sigla: sigla?.toString()?.toUpperCase()||null,
      status: status?.toString()||null,
      limit: limit? parseInt(limit,10): 100,
      offset: offset? parseInt(offset,10): 0,
      prefixScope: prefix
    });
    res.json(rows);
  }catch(e){ next(e); }
});

// Criar/Atualizar (admin)
empregados.post('/', requireAuth, requireAdmin, adminLimiter, async (req,res,next)=>{
  try{
    const obj = empregadoCreate.parse(req.body);
    const id = await svc.upsertEmpregado(obj);
    res.status(201).json({ ok:true, registro:id });
  }catch(e){ next(e); }
});

empregados.put('/:registro', requireAuth, requireAdmin, adminLimiter, async (req,res,next)=>{
  try{
    const merged = { ...req.body, registro: req.params.registro };
    const obj = empregadoUpdate.parse(merged);
    const id = await svc.upsertEmpregado(obj);
    res.json({ ok:true, registro:id });
  }catch(e){ next(e); }
});

empregados.delete('/:registro', requireAuth, requireAdmin, adminLimiter, async (req,res,next)=>{
  try{
    await svc.deleteEmpregado(req.params.registro);
    res.json({ ok:true });
  }catch(e){ next(e); }
});
```

#### `src/routes/upload.js` (upload e conversão da imagem)

```js
import { Router } from 'express';
import multer from 'multer';
import sharp from 'sharp';
import fs from 'node:fs/promises';
import path from 'node:path';
import { cfg } from '../config.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { query } from '../db.js';
import { publicLimiter } from '../middleware/rateLimit.js';

export const upload = Router();

const storage = multer.memoryStorage();
const up = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (_req, file, cb) => {
    if (!/^image\/(jpeg|png)$/i.test(file.mimetype)) return cb(new Error('Formato inválido (use JPG/PNG)'));
    cb(null, true);
  }
});

upload.post('/upload-foto/:registro', requireAuth, requireAdmin, publicLimiter, up.single('file'), async (req,res,next)=>{
  try{
    const registro = req.params.registro;
    if (!/^[0-9]{6}$/.test(registro)) return res.status(400).json({ error:'invalid_registro' });
    if (!req.file) return res.status(400).json({ error:'file_required' });

    const dest = path.join(cfg.fotosDir, `${registro}.jpg`);

    // Converte para JPG padrão (qualidade 82)
    const jpg = await sharp(req.file.buffer).rotate().jpeg({ quality: 82, mozjpeg: true }).toBuffer();
    await fs.writeFile(dest, jpg, { mode: 0o644 });

    // Atualiza caminho no banco
    await query('update public.empregados set foto_path=$1, updated_at=now() where registro=$2', [`${registro}.jpg`, registro]);

    res.json({ ok:true, foto_path: `${registro}.jpg` });
  }catch(e){ next(e); }
});
```

### 5.13 `src/app.js` e `src/index.js`

```js
// src/app.js
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import { corsMw } from './middleware/cors.js';
import { notFound, errorHandler } from './middleware/errors.js';

import { auth } from './routes/auth.js';
import { credenciais } from './routes/credenciais.js';
import { unidades } from './routes/unidades.js';
import { empregados } from './routes/empregados.js';
import { upload } from './routes/upload.js';

export function createApp(){
  const app = express();
  app.disable('x-powered-by');

  app.use(helmet());
  app.use(corsMw);
  app.use(compression());
  app.use(express.json({ limit:'1mb' }));
  app.use(morgan('combined'));

  app.get('/health', (_req,res)=>res.json({ ok:true }));

  app.use('/api/auth', auth);
  app.use('/api/credenciais', credenciais);
  app.use('/api/unidades', unidades);
  app.use('/api/empregados', empregados);
  app.use('/api', upload); // /api/upload-foto/:registro

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
```

```js
// src/index.js
import { createApp } from './app.js';
import { cfg } from './config.js';

const app = createApp();
app.listen(cfg.port, ()=>{
  console.log(`API CETESB Credenciais: porta ${cfg.port} (env=${cfg.env})`);
});
```

---

## 6) CONTRATO DA API (ENDPOINTS, FILTROS, EXEMPLOS)

**Base URL (produção):** `https://<api.cetesb.sp.gov.br>/credenciais/api`

| Método | Rota | Acesso | Descrição |
|---|---|---|---|
| GET | `/empregados/:registro` | Público | Dados para página pública (QR). |
| GET | `/empregados` | Gerente/Admin | Lista com filtros (`q`, `sigla`, `status`, `limit`, `offset`). |
| POST | `/empregados` | Admin | Cria/atualiza (upsert). |
| PUT | `/empregados/:registro` | Admin | Atualiza registro. |
| DELETE | `/empregados/:registro` | Admin | Exclui registro. |
| POST | `/upload-foto/:registro` | Admin | Upload/replace da foto (multipart, campo `file`). |
| GET | `/unidades` | Público/Restrito | Catálogo para combos. |
| GET | `/credenciais` | Público/Restrito | Catálogo para combos. |
| POST | `/auth/login` | Público | (Opcional) Emite JWT para admin/gerente (piloto). |

**Status derivado (front-end):**  
- `Em andamento` → amarelo;  
- `Ativo` com `validade ≥ hoje` → verde;  
- Caso contrário → vermelho (`Inativo`).

**Exemplos (curl):**

```bash
# Pública (QR)
curl https://site.cetesb.sp.gov.br/credenciais/api/empregados/000001

# Login (piloto)
curl -X POST https://api.../credenciais/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"matricula":"008031","password":"cetesb"}'
# → {"token":"...","nivel":2,"sigla":"ARAS"}

# Lista (admin/gerente)
curl "https://api.../credenciais/api/empregados?q=FABIO&sigla=ARAS" \
  -H "Authorization: Bearer <TOKEN>"

# Criação/atualização (admin)
curl -X POST https://api.../credenciais/api/empregados \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"registro":"000001","cred_num":"1234","cred_cod":1,"status":"Ativo","nome":"NOME","sigla":"ARAS","validade":"2026-12-31"}'

# Upload de foto (admin)
curl -X POST https://api.../credenciais/api/upload-foto/000001 \
  -H "Authorization: Bearer <TOKEN>" \
  -F "file=@/caminho/para/000001.jpg"
```

---

## 7) FRONT-END ESTÁTICO (HTML/CSS/JS) — ESTRUTURA E INTEGRAÇÃO

### 7.1 Estrutura

```
/var/www/credenciais/
├─ index.html              # Login restrito
├─ admin.html              # Cadastro (CRUD + upload)
├─ consulta.html           # Consulta (filtros + abertura da pública)
├─ public.html             # Página pública (QR Code)
├─ change-password.html    # Troca de senha (se aplicável)
├─ style.css               # Estilos
├─ config.json             # Config do ambiente
└─ fotos/                  # Imagens (servidas como estático)
```

### 7.2 `config.json` (produção, falando com a API própria)

```json
{
  "API_BASE_URL": "https://api.cetesb.sp.gov.br/credenciais/api",
  "FOTOS_BASE_URL": "https://site.cetesb.sp.gov.br/credenciais/fotos",
  "PUBLIC_PAGE": "public.html",
  "BASE_URL": "https://site.cetesb.sp.gov.br/credenciais"
}
```

### 7.3 Integração (pontos-chave do JS)

**Função utilitária para chamadas autenticadas:**

```html
<script type="module">
const cfg = await (await fetch('config.json', {cache:'no-store'})).json();
function api(path, opts={}){
  const token = localStorage.getItem('token');
  const headers = { 'Content-Type':'application/json', ...(opts.headers||{}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  return fetch(`${cfg.API_BASE_URL}${path}`, { ...opts, headers });
}
</script>
```

**Carregar catálogos (ex.: `admin.html`):**
```js
const cred = await (await api('/credenciais')).json();
document.querySelector('#cred_cod').innerHTML =
  cred.map(c=>`<option value="${c.cred_cod}">${c.cred_cod} — ${c.descricao}</option>`).join('');

const unid = await (await api('/unidades')).json();
document.querySelector('#sigla').innerHTML =
  '<option value="">Selecione…</option>'+unid.map(u=>`<option value="${u.sigla}">${u.sigla}</option>`).join('');
```

**Salvar empregado (POST `/empregados`):**
```js
await api('/empregados', {
  method:'POST',
  body: JSON.stringify({
    registro, cred_num, cred_cod, status, nome, sigla, nome_da_unidade, validade, doe:null
  })
});
```

**Upload de foto:**
```js
const fd = new FormData();
fd.append('file', fileInput.files[0]);
await fetch(`${cfg.API_BASE_URL}/upload-foto/${registro}`, {
  method:'POST',
  headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
  body: fd
});
```

**Página pública (`public.html`) — obter registro da URL e renderizar:**

```js
const params = new URLSearchParams(location.search);
const reg = params.get('reg');
const r = await fetch(`${cfg.API_BASE_URL}/empregados/${reg}`);
if (r.ok){
  const emp = await r.json();
  // status efetivo:
  const hoje = new Date(); const v = new Date(emp.validade+'T00:00:00');
  let chip = 'Inativo';
  if (emp.status === 'Em andamento') chip = 'Em andamento';
  else if (emp.status === 'Ativo' && v >= new Date(hoje.getFullYear(),hoje.getMonth(),hoje.getDate())) chip = 'Ativo';
  document.querySelector('#statusChip').textContent = chip;
  document.querySelector('#foto').src = `${cfg.FOTOS_BASE_URL}/${emp.foto_path||'placeholder.jpg'}`;
  // preencher demais campos (nome, sigla, unidade, etc.)
} else {
  // registro não encontrado
}
```

> **Responsividade e identidade visual:** o `style.css` já contém tokens e componentes no padrão e-CETESB (cores brand, chips de status etc.).

---

## 8) SEGURANÇA (DB, API, WEB) E CONFORMIDADE

- **Banco**: separar papéis de leitura/escrita; nunca expor o DB diretamente; backups diários.  
- **API**: TLS, CORS restrito ao domínio oficial, rate-limit, validações (zod), SQL parametrizado e logs.  
- **Fotos**: apenas leitura pública; gravação exclusiva pelo serviço API.  
- **Autenticação**: preferir **SSO corporativo** (Azure AD). Esqueleto com JWT incluído para implantação rápida.  
- **Logs**: anonimizar quando necessário; reter por período mínimo.  
- **Privacidade**: expor somente dados estritamente necessários na página pública.

---

## 9) DEPLOY NO SITE PÚBLICO DA CETESB (NGINX + SYSTEMD)

### 9.1 Front-end
- Copiar arquivos estáticos para `/var/www/credenciais/`.  
- Pasta de fotos: `/var/www/credenciais/fotos/` (criar e dar permissão `chown apiuser:www-data`).  
- Atualizar `config.json` com URLs finais.

### 9.2 API (systemd)
Arquivo `/etc/systemd/system/cetesb-credenciais.service`:
```ini
[Unit]
Description=CETESB Credenciais API
After=network.target

[Service]
Environment=NODE_ENV=production
WorkingDirectory=/opt/cetesb-credenciais/backend
ExecStart=/usr/bin/node src/index.js
Restart=always
User=apiuser
Group=apiuser
EnvironmentFile=/opt/cetesb-credenciais/backend/.env
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cetesb-credenciais
sudo systemctl start cetesb-credenciais
```

### 9.3 NGINX (site + proxy)

```nginx
server {
  listen 443 ssl http2;
  server_name site.cetesb.sp.gov.br;

  root /var/www/credenciais;
  index index.html;

  # CSP básica
  add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' https://api.cetesb.sp.gov.br" always;

  # Estáticos
  location ~* \.(css|js|png|jpg|jpeg|svg|ico)$ {
    add_header Cache-Control "public, max-age=3600";
  }

  # Fotos públicas
  location /fotos/ {
    alias /var/www/credenciais/fotos/;
    add_header Cache-Control "public, max-age=3600";
  }

  # API (backend)
  location /credenciais/api/ {
    proxy_pass http://127.0.0.1:8080/api/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

---

## 10) PLANO DE TESTES E VALIDAÇÕES

1. **DB**: criar tabelas, seeds (`credenciais`, `unidades`), inserir 1 `empregado` teste.  
2. **API**: `GET /health`, `GET /empregados/:registro` (público), `POST /empregados` (admin), `POST /upload-foto/:registro`.  
3. **Front-end**:  
   - `index.html`: login (gera `localStorage.token`).  
   - `admin.html`: carregar combos, salvar registro, subir foto, listar e filtrar.  
   - `consulta.html`: filtros por nome/sigla/status; abrir pública.  
   - `public.html`: QR `?reg=000001` renderiza cartão e foto.  
4. **Segurança**: CORS restrito, TLS, rate-limit, inputs inválidos (regex).  
5. **Carga CSV**: importar `unidades.csv` grande; testar performance.  
6. **Backups**: dump/restore.

---

## 11) OPERAÇÃO, LOGS, BACKUPS E RESTAURAÇÃO

- **Logs API**: `/var/log/syslog` (ou journald); considerar rotação.  
- **Backup DB**: `pg_dump -Fc credenciais > backup.dump` diário + retenção.  
- **Restore**: `pg_restore -d credenciais backup.dump`.  
- **Backup fotos**: snapshot diário de `/var/www/credenciais/fotos/`.  
- **Monitoramento**: ping `/health`, métricas básicas (conexões, erros 5xx).

---

## 12) APÊNDICES (OpenAPI, NGINX, scripts utilitários)

### 12.1 OpenAPI (resumo)
```yaml
openapi: 3.0.3
info:
  title: CETESB Credenciais API
  version: 1.0.0
servers:
  - url: https://api.cetesb.sp.gov.br/credenciais/api
paths:
  /empregados/{registro}:
    get:
      summary: Consulta pública por registro
      parameters:
        - in: path
          name: registro
          required: true
          schema: { type: string, pattern: '^[0-9]{6}$' }
      responses:
        '200': { description: OK }
        '404': { description: Não encontrado }
  /empregados:
    get:
      summary: Lista com filtros (gerente/admin)
      parameters:
        - in: query
          name: q
          schema: { type: string }
        - in: query
          name: sigla
          schema: { type: string }
        - in: query
          name: status
          schema: { type: string, enum: [Ativo, Em andamento, Inativo] }
        - in: query
          name: limit
          schema: { type: integer, default: 100, maximum: 500 }
        - in: query
          name: offset
          schema: { type: integer, default: 0 }
      responses:
        '200': { description: OK }
  /upload-foto/{registro}:
    post:
      summary: Upload/replace foto (admin)
      parameters:
        - in: path
          name: registro
          required: true
          schema: { type: string, pattern: '^[0-9]{6}$' }
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file:
                  type: string
                  format: binary
      responses:
        '200': { description: OK }
```

### 12.2 Script utilitário — criação rápida de papéis/usuários

```sql
-- Executar como superuser do PostgreSQL
create role app_read noinherit;
create role app_write noinherit;
grant app_read to app_write;

-- Usuários de aplicação
create user api_backend with password '***';
grant app_write to api_backend;

create user api_public with password '***';
grant app_read to api_public;

-- Grants básicos
grant usage on schema public to app_read, app_write;
grant select on all tables in schema public to app_read;
alter default privileges in schema public grant select on tables to app_read;
grant insert, update, delete on table public.empregados to app_write;
```

### 12.3 Observações finais de integração
- Substituir no front-end as chamadas atuais do piloto (Supabase) por chamadas à **API CETESB** via `config.json` (`API_BASE_URL`, `FOTOS_BASE_URL`).  
- O **layout** e a **lógica de status** já estão descritos aqui; a TI pode reconstruir as páginas com base nas seções 7.1–7.3 e CSS e-CETESB (cores, chips, tabelas, formulários).  
- Para SSO corporativo, substituir o `/auth/login` por validação de cabeçalho de identidade no **proxy** (ex.: `X-User-Id`) e preencher `usuarios_app` via script administrativo.
