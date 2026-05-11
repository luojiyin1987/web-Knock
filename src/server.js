import { createKnockServer } from "./app.js";

const { server, config, demo } = await createKnockServer();

server.listen(config.port, () => {
  console.log(`Knock auth gateway listening on http://localhost:${config.port}`);
  console.log("Demo clients:", demo.clients);
  console.log("Demo users:", demo.users);
});
