import "reflect-metadata";
import Koa from "koa";
import Router from "koa-router";
import bodyParser from "koa-bodyparser";
import { AppDataSource } from "./data-source";
import { User } from "./entity/User";

const app = new Koa();
const router = new Router();

app.use(bodyParser());

router.get("/", async (ctx) => {
  ctx.body = { message: "Autenticação ok!" };
});

app.use(router.routes()).use(router.allowedMethods());

AppDataSource.initialize()
  .then(() => {
    console.log("Conectado ao banco de dados!");

    app.listen(3000, () => {
      console.log("O serviço está rodando no endereço - http://localhost:3000");
    });


    createTestUser();
  })
  .catch((error) => console.error("Erro ao conectar ao banco de dados:", error));


// teste para criação de usuario manualmente
async function createTestUser() {
  const userRepository = AppDataSource.getRepository(User);

  const user = new User();
  user.name = "joseTeste2";
  user.email = "teste2@example.com";
  user.role = "adminTest";

  await userRepository.save(user);
  console.log("Usuário criado com sucesso:", user);
}
