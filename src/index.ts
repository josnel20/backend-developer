import dotenv from 'dotenv';
import Koa from "koa";
import Router from "koa-router";
import bodyParser from "koa-bodyparser";
import session from "koa-session";
import { CognitoIdentityProviderClient, InitiateAuthCommand } from "@aws-sdk/client-cognito-identity-provider";
import { AuthFlowType } from "@aws-sdk/client-cognito-identity-provider";
import crypto from "crypto";
import jwt from "jsonwebtoken"; 
import { Middleware } from "koa";
dotenv.config();

// Inicializando o Koa
const app = new Koa();
const router = new Router();

const COGNITO_USER_POOL_ID = "us-east-1_35znuAYPN";
const cognitoRegiao: string = process.env.COGNITO_REGION as string;
const cognitoClienteId: string = process.env.COGNITO_CLIENT_ID as string;
const cognitoSecretClient: string = process.env.COGNITO_SECRET_CLIENT as string;

interface TokenSet {
  idToken: string;
  accessToken: string;
  refreshToken: string;
}

interface LoginRequestBody {
  username: string;
  password: string;
}

if (!cognitoClienteId || !cognitoSecretClient) {
  throw new Error("COGNITO_CLIENT_ID ou COGNITO_SECRET_CLIENT não estão definidos, olhar no .env");
}

//FUNÇÕES ÚTEIS...
// Geração do Secret Hash - AWS
function generateSecretHash(username: string, clientId: string, clientSecret: string): string {
  const hmac = crypto.createHmac("sha256", clientSecret);
  hmac.update(username + clientId); // username + clientId
  return hmac.digest("base64");
}

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
    AuthFlow: "USER_PASSWORD_AUTH" as AuthFlowType, // Tipo correto para o AuthFlow
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
router.post("/login", async (ctx) => {
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

// usabilidade das rotas
app.use(router.routes()).use(router.allowedMethods());

// Iniciando o servidor
app.listen(3000, () => {
  console.log("Servidor rodando em http://localhost:3000");
});