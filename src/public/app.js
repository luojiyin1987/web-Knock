const output = document.querySelector("#output");
const clearButton = document.querySelector("#clear-output");
const callbackPath = new URLSearchParams(window.location.search).get("callback");

function writeOutput(payload) {
  output.textContent = JSON.stringify(payload, null, 2);
}

async function submitJson(url, payload, headers = {}) {
  const response = await fetch(url, {
    method: payload ? "POST" : "GET",
    headers: {
      "content-type": "application/json",
      ...headers
    },
    body: payload ? JSON.stringify(payload) : undefined
  });

  const data = await response.json();
  writeOutput({
    status: response.status,
    data
  });

  return data;
}

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const data = await submitJson("/v1/auth/login", Object.fromEntries(form.entries()));

  if (data.accessToken) {
    document.querySelector('#session-form textarea[name="accessToken"]').value = data.accessToken;
    document.querySelector('#introspect-form textarea[name="token"]').value = data.accessToken;
    document.querySelector('#refresh-form textarea[name="refreshToken"]').value = data.refreshToken;
    document.querySelector('#logout-form textarea[name="accessToken"]').value = data.accessToken;
    document.querySelector('#logout-form textarea[name="refreshToken"]').value = data.refreshToken;

    if (callbackPath) {
      window.location.assign(callbackPath);
    }
  }
});

document.querySelector("#session-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const accessToken = form.get("accessToken");
  await submitJson("/v1/auth/session", null, {
    authorization: `Bearer ${accessToken}`
  });
});

document.querySelector("#refresh-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const data = await submitJson("/v1/auth/refresh", Object.fromEntries(form.entries()));

  if (data.accessToken) {
    document.querySelector('#session-form textarea[name="accessToken"]').value = data.accessToken;
    document.querySelector('#introspect-form textarea[name="token"]').value = data.accessToken;
    document.querySelector('#refresh-form textarea[name="refreshToken"]').value = data.refreshToken;
    document.querySelector('#logout-form textarea[name="accessToken"]').value = data.accessToken;
    document.querySelector('#logout-form textarea[name="refreshToken"]').value = data.refreshToken;
  }
});

document.querySelector("#introspect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  await submitJson("/v1/auth/introspect", Object.fromEntries(form.entries()));
});

document.querySelector("#logout-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const accessToken = form.get("accessToken");
  const refreshToken = form.get("refreshToken");
  await submitJson(
    "/v1/auth/logout",
    { refreshToken, accessToken },
    accessToken ? { authorization: `Bearer ${accessToken}` } : {}
  );
});

clearButton.addEventListener("click", () => {
  writeOutput({});
});
