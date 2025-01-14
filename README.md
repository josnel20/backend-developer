# Aplicação Koa com Integração AWS Cognito e PostgreSQL

Esta é uma aplicação desenvolvida em Node.js usando o framework Koa. Ela integra autenticação com AWS Cognito e utiliza um banco de dados PostgreSQL para gerenciar usuários.

Para exibir a documentação swegger; localize o arquivo doc.yaml e no seu editor de código (vsc), instale a biblioteca `openAPI SwaggerUI preview`

## Requisitos

Certifique-se de que as seguintes ferramentas estão instaladas no seu ambiente:

- Node.js (versão mais recente recomendada)  
- NPM ou Yarn (para gerenciar pacotes)  
- PostgreSQL (com acesso ao banco de dados configurado)  
- AWS CLI (opcional, para configurar o Cognito)  
- Arquivo `.env` com as variáveis de ambiente necessárias  

---

## Configuração

### Instalação das Dependências

Clone este repositório e instale as dependências necessárias:

```bash
git clone <URL_DO_REPOSITORIO>
cd <NOME_DO_REPOSITORIO>
npm install
```

### Configuração do `.env`

Crie um arquivo `.env` na raiz do projeto e adicione as seguintes variáveis de ambiente:

```dotenv
DATABASE_USER=<seu_usuario>
DATABASE_HOST=<seu_host>
DATABASE_NAME=<seu_banco>
DATABASE_PASSWORD=<sua_senha>
DATABASE_PORT=<porta_do_postgresql>

COGNITO_USER_POOL_ID=<seu_user_pool_id>
COGNITO_REGION=<sua_regiao>
COGNITO_CLIENT_ID=<seu_client_id>
COGNITO_SECRET_CLIENT=<seu_secret_client>
```

---

### Banco de Dados

Certifique-se de que o banco de dados PostgreSQL está configurado e acessível. Você pode criar a tabela `user` usando a seguinte query SQL:

```sql
CREATE TABLE public.user (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    is_onboarded BOOLEAN DEFAULT FALSE
);
```

---

## Uso

### Inicializar o Servidor

Inicie o servidor com o comando:

```bash
npm start
```

O servidor estará disponível em: [http://localhost:3000](http://localhost:3000).

---

### Rotas Disponíveis

#### 1. **Autenticação**

- **Endpoint:** `POST /auth`  
- **Descrição:** Autentica o usuário no AWS Cognito e retorna os tokens.  
- **Body:**  

  ```json
  {
    "username": "seu_username",
    "password": "sua_senha"
  }
  ```

---

#### 2. **Informações do Usuário**

- **Endpoint:** `POST /me`  
- **Descrição:** Verifica se o usuário já existe no banco de dados ou cria um novo.  
- **Body:**  

  ```json
  {
    "email": "user@example.com",
    "role": "admin",
    "name": "Nome do Usuário"
  }
  ```

- **Autenticação:** Token JWT necessário no cabeçalho.  

---

#### 3. **Editar Conta**

- **Endpoint:** `POST /edit-account`  
- **Descrição:** Permite que um usuário edite suas informações, respeitando os níveis de permissão.  
- **Body:**  

  ```json
  {
    "name": "Novo Nome",
    "role": "admin",
    "idUser": 1
  }
  ```

- **Autenticação:** Token JWT necessário no cabeçalho.  

---

### Middleware de Autorização

- O middleware verifica o token JWT do Cognito para proteger as rotas `/me` e `/edit-account`.  
- Usuários com escopo `aws.cognito.signin.user.admin` possuem permissões adicionais.  

---

### Logs e Mensagens

- Erros e mensagens importantes são registrados no console.  
- Verifique a saída do terminal para informações de debugging.  

---

## Estrutura do Projeto

```plaintext
├── data-source.ts        # Configuração de conexão com o banco de dados
├── .env                  # Variáveis de ambiente (não versionar)
├── index.ts              # Inicialização do servidor e definição de rotas
├── package.json          # Dependências e scripts
├── README.md             # Documentação
```

---

## Dependências

As principais dependências incluem:

- `koa`: Framework para servidor web  
- `koa-router`: Gerenciamento de rotas  
- `koa-bodyparser`: Parsing de JSON no body das requisições  
- `koa-session`: Gerenciamento de sessões  
- `@aws-sdk/client-cognito-identity-provider`: Integração com AWS Cognito  
- `pg`: Cliente PostgreSQL para Node.js  
- `dotenv`: Carregar variáveis de ambiente  

---

## Contribuição

Se você encontrar bugs ou quiser sugerir melhorias, envie uma Pull Request ou abra uma Issue.

---

