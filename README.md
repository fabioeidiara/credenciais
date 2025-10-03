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
