import Koa from "koa";
import Router from "koa-router";
import bodyParser from "koa-bodyparser";
import { AppDataSource } from "./data-source";

const app = new Koa();
const router = new Router();

app.use(bodyParser());

router.get("/", async (ctx) => {
  ctx.body = { message: "Autenticação ok!" };
});

app.use(router.routes()).use(router.allowedMethods());

AppDataSource.initialize()
  .then(() => {
    console.log("Connectado ao database!");
    app.listen(3000, () => {
      console.log("O serviço esta rodando no endereço -  http://localhost:3000");
    });
  })
  .catch((error) => console.log("Erro ao conectar ao database:", error));
