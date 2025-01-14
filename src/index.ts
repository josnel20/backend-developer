import dotenv from 'dotenv';
import Koa from "koa";
import Router from "koa-router";
import { AppDataSource } from "./data-source";
import bodyParser from "koa-bodyparser";
import session from "koa-session";
import { CognitoIdentityProviderClient, InitiateAuthCommand } from "@aws-sdk/client-cognito-identity-provider";
import { AuthFlowType } from "@aws-sdk/client-cognito-identity-provider";
import crypto from "crypto";
import jwt from "jsonwebtoken"; 
import jwksClient from "jwks-rsa";
import { Middleware } from "koa";
import { Client } from "pg";

dotenv.config();

// Inicializando o Koa
const app = new Koa();
const router = new Router();

AppDataSource.initialize()
  .then(() => {
    console.log("Database Conectado com sucesso!");

    app.listen(3000, () => {
      console.log(`O serviço está rodando na porta: http://localhost:3000`);
    });
  })
  .catch((error) => console.error("Erro ao conectar ao Database: ", error));


const COGNITO_USER_POOL_ID: string = process.env.COGNITO_USER_POOL_ID as string;
const cognitoRegiao: string = process.env.COGNITO_REGION as string;
const cognitoClienteId: string = process.env.COGNITO_CLIENT_ID as string;
const cognitoSecretClient: string = process.env.COGNITO_SECRET_CLIENT as string;

// Conexão com o banco de dados PostgreSQL
const dbClient = new Client({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  port: Number(process.env.DATABASE_PORT),
});

// Iniciar a conexão com o banco de dados
dbClient.connect();

interface TokenSet {
  idToken: string;
  accessToken: string;
  refreshToken: string;
}

interface LoginRequestBody {
  username: string;
  password: string;
}

interface meRequestBody {
  email: string;
  role: string;
  name: string;
}

interface editRequestBody {
  name: string;
  role: string;
  idUser: number;
}

interface DecodedToken {
  scope: string[];
}

if (!cognitoClienteId || !cognitoSecretClient) {
  throw new Error("COGNITO_CLIENT_ID ou COGNITO_SECRET_CLIENT não estão definidos, olhar no .env");
}

// FUNÇÕES ÚTEIS...
// Geração do Secret Hash - AWS
function generateSecretHash(username: string, clientId: string, clientSecret: string): string {
  const hmac = crypto.createHmac("sha256", clientSecret);
  hmac.update(username + clientId); // username + clientId
  return hmac.digest("base64");
}

const client = jwksClient({
  jwksUri: `https://cognito-idp.${cognitoRegiao}.amazonaws.com/${COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
});

function getKey(header: any, callback: any) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err, null);
    } else {
      const signingKey = key?.getPublicKey();
      callback(null, signingKey);
    }
  });
}

//5-Middleware de Autorização
const authMiddleware: Middleware = async (ctx, next) => {
  const authHeader = ctx.headers.authorization;

  if (!authHeader) {
    ctx.status = 401;
    ctx.body = { message: "Token de autorização não fornecido." };
    return;
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(
        token,
        getKey,
        {
          algorithms: ["RS256"],
        },
        (err, decoded) => {
          if (err) reject(err);
          resolve(decoded);
        }
      );
    });

    ctx.state.user = decoded;
    await next();
  } catch (err) {
    console.error("Erro ao verificar o token:", err);
    ctx.status = 403;
    ctx.body = { message: "Token inválido ou expirado." };
  }
};

const authMiddlewareAdm: Middleware = async (ctx, next) => {
  const authHeader = ctx.headers.authorization;

  if (!authHeader) {
    ctx.status = 401;
    ctx.body = { message: "Token de autorização não fornecido." };
    return;
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = await new Promise<DecodedToken>((resolve, reject) => {
      jwt.verify(
        token,
        getKey,
        {
          algorithms: ["RS256"],
        },
        (err, decoded) => {
          if (err) reject(err);
          resolve(decoded as DecodedToken);
        }
      );
    });

    ctx.state.user = decoded;

    // Validação de escopo de administrador
    const hasAdminScope = decoded.scope && decoded.scope.includes("aws.cognito.signin.user.admin");

    if (hasAdminScope) {
      console.log("Usuário é administrador");
    } else {
      console.log("Usuário não tem permissões de administrador");
    }

    await next();
  } catch (err) {
    console.error("Erro ao verificar o token:", err);
    ctx.status = 403;
    ctx.body = { message: "Token inválido ou expirado." };
  }
};

app.use(bodyParser());
app.keys = [cognitoSecretClient];
app.use(
  session(
    {
      key: "sess",
      maxAge: 86400000, 
    },
    app
  )
);

// 4- Integração com AWS Cognito - Função para autenticar o usuário com Cognito
async function authenticateUser(username: string, password: string): Promise<TokenSet> {
  const secretHash = generateSecretHash(username, cognitoClienteId, cognitoSecretClient);
  console.log("Secret Hash gerado:", secretHash);

  const authParams = {
    AuthFlow: "USER_PASSWORD_AUTH" as AuthFlowType,
    ClientId: cognitoClienteId,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
      SECRET_HASH: secretHash,
    },
  };

  const cognitoIdentityProviderClient = new CognitoIdentityProviderClient({
    region: cognitoRegiao,
  });

  const command = new InitiateAuthCommand(authParams);

  try {
    const response = await cognitoIdentityProviderClient.send(command);
    return {
      idToken: response.AuthenticationResult?.IdToken!,
      accessToken: response.AuthenticationResult?.AccessToken!,
      refreshToken: response.AuthenticationResult?.RefreshToken!,
    };
  } catch (error) {
    console.error("Erro de autenticação:", error);
    throw error;
  }
}

// 7 - CRIAÇÃO DAS ROTAS
// A rota /auth deverá ser pública, a rota /me e /edit-account devem ser protegidas pelo JWT retornado pelo Cognito
router.post("/auth", async (ctx) => {
  try {
    const body = ctx.request.body as LoginRequestBody;
    const { username, password } = body;

    // validar request (passado pelo body da requisição)...
    console.log("dados Recebidos da api", body);

    if (!username || !password) {
      ctx.status = 400;
      ctx.body = { message: "Usuário e senha são em falta." };
      return;
    }

    const tokenSet = await authenticateUser(username, password);

    if (ctx.session) {
        ctx.session.tokenSet = tokenSet;
    } else {
      ctx.status = 500;
      ctx.body = { message: "Sessão não inicializada." };
      return;
    }

    ctx.body = { message: "Login realizado com sucesso!", tokenSet };

    console.log("Solicitação realizada com sucesso, login ok");
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : "Erro Não detectado.";
    console.error("Erro identificado na rota /login:", errorMessage);
    ctx.status = 500;
    ctx.body = { message: `Erro durante o login: ${errorMessage}` };
  }
});

// A rota /me servirá como um signInOrRegister, onde deverá verificar se o usuário já existe, senão criar em nosso banco de dados
router.post("/me", authMiddleware, async (ctx) => {
  const { email, role, name } = ctx.request.body as meRequestBody;

  // Validação de campos obrigatórios
  if (!email || !role || !name) {
    ctx.status = 400;
    ctx.body = { message: "Os campos: Email, role e name são obrigatórios." };
    return;
  }

  try {
  
    const userResult = await dbClient.query("SELECT * FROM public.user WHERE email = $1", [email]);

    if (userResult.rows.length > 0) {
      console.log("Login bem-sucedido", userResult);

      ctx.body = { message: "Login bem-sucedido", userResult };
    } else {

      console.log("Usuário não encontrado. Criando novo usuário...");

      const createUserQuery = `INSERT INTO public."user" (email, role, name) VALUES ($1, $2, $3) RETURNING id, email, role, name;`;
      const newUserResult = await dbClient.query(createUserQuery, [email, role, name]);

      if (newUserResult.rows.length > 0) {
        const newUser = newUserResult.rows[0];
        ctx.status = 201;

        console.log("Novo Usuário criado com sucesso", newUser);
        ctx.body = { message: "Novo usuário criado com sucesso", user: newUser };
      } else {
        throw new Error("Falha ao criar novo usuário.");
      }
    }
  } catch (err) {
    console.error("Erro no processo de autenticação:", err);
    ctx.status = 500;
    ctx.body = { message: "Erro interno do servidor" };
  }
});

// Para a rota /edit-account os usuários com escopo de admin, poderão alterar as informações de nome e role, enquanto os usuários com escopo de usuário somente poderão alterar o seu nome, após alterar o nome, a flag de isOnboarded deve ser modificada para true.
router.post("/edit-account", authMiddleware, async (ctx) => {
  const user = ctx.state.user;
  const { name, role, idUser } = ctx.request.body as editRequestBody 

  if (!name && !role) {
    ctx.status = 400;
    ctx.body = { message: "Os campos nome e role devem ser fornecidos." };
    return;
  }

  if (!idUser) {
    ctx.status = 400;
    ctx.body = { message: "O campo idUser é obrigatório." };
    return;
  }

  try {
    if (user.scope.includes("aws.cognito.signin.user.admin")) {

      const updateAdminQuery = `UPDATE public."user" SET name = $1, role = $2 WHERE id = $3 RETURNING id, email, name, role;`;
      const result = await dbClient.query(updateAdminQuery, [name, role, idUser]);

      if (result.rows.length > 0) {
        ctx.status = 200;
        ctx.body = { message: "Informações do usuário atualizadas com sucesso.", user: result.rows[0] };
      } else {
        ctx.status = 404;
        ctx.body = { message: "Usuário não encontrado." };
      }
    } else if (user.scope.includes("user")) {
      // Usuário comum
      if (user.id !== idUser) {
        ctx.status = 403;
        ctx.body = { message: "Usuários só podem alterar suas próprias informações." };
        return;
      }

      if (!name) {
        ctx.status = 400;
        ctx.body = { message: "Usuários só podem atualizar o nome." };
        return;
      }

      const updateUserQuery = `UPDATE public."user" SET name = $1, "isOnboarded" = true WHERE id = $2 RETURNING id, email, name, "isOnboarded";`;
      const result = await dbClient.query(updateUserQuery, [name, idUser]);

      if (result.rows.length > 0) {
        ctx.status = 200;
        ctx.body = { message: "Nome atualizado com sucesso.", user: result.rows[0] };
      } else {
        ctx.status = 404;
        ctx.body = { message: "Usuário não encontrado." };
      }
    } else {
      ctx.status = 403;
      ctx.body = { message: "Acesso negado. Escopo inválido." };
    }
  } catch (err) {
    console.error("Erro ao atualizar informações do usuário:", err);
    ctx.status = 500;
    ctx.body = { message: "Erro interno do servidor." };
  }
});

// A rota /users deverá ser protegida e somente os usuários com escopo de admin poderão acessa-lá, essa rota retornara todos os usuários cadastrados em nosso banco
router.get("/users", authMiddlewareAdm, async (ctx) => {
  try {
    const user = ctx.state.user;
    if (!user || !user.scope.includes("aws.cognito.signin.user.admin")) {
      ctx.status = 403;
      ctx.body = { message: "Acesso negado. Somente administradores podem acessar esta rota." };
      return;
    }

    const result = await dbClient.query("SELECT id, name, email, role FROM public.user");

    const users = result.rows;
    ctx.body = { users };
  } catch (err) {
    console.error("Erro ao buscar os usuários da tabela:", err);
    ctx.status = 500;
    ctx.body = { message: "Erro ao buscar os usuários da tabela." };
  }
});

app.use(router.routes()).use(router.allowedMethods());