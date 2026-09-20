(function () {
  "use strict";

  var apiRoot = "/api/komari-passkey";
  var state = {
    status: null,
    statusRequest: null,
  };
  var messages = {
    en: {
      passkey: "Passkey",
      login: "Sign in with Passkey",
      add: "Add passkey",
      delete: "Delete",
      cancel: "Cancel",
      register: "Register passkey",
      deleteTitle: "Delete passkey",
      deleteCopy: "This passkey will no longer be able to sign in.",
      addTitle: "Add a passkey",
      name: "Passkey name",
      defaultName: "Passkey",
      noPasskeys: "No passkeys have been added.",
      notConfigured: "Passkey is not configured.",
      unavailable: "Passkey verifier is unavailable.",
      loading: "Loading...",
      added: "Added",
      lastUsed: "Last used",
      operationFailed: "The passkey operation could not be completed.",
      configurationRequired: "Passkey is not configured.",
      challengeExpired: "The passkey request has expired. Try again.",
      credentialLimit: "The passkey limit has been reached.",
      passkeyUnavailable: "No passkey is available.",
      verificationFailed: "Passkey verification failed.",
      syncedCredentialsNotAllowed: "This passkey is synced by its provider. Enable synced passkeys in the plugin security policy to use it.",
      authenticationRequired: "Your session has expired.",
    },
    "zh-CN": {
      passkey: "通行密钥",
      login: "通过通行密钥登录",
      add: "添加通行密钥",
      delete: "删除",
      cancel: "取消",
      register: "注册通行密钥",
      deleteTitle: "删除通行密钥",
      deleteCopy: "删除后，该通行密钥将不能再用于登录。",
      addTitle: "添加通行密钥",
      name: "通行密钥名称",
      defaultName: "通行密钥",
      noPasskeys: "尚未添加通行密钥。",
      notConfigured: "尚未配置通行密钥。",
      unavailable: "通行密钥验证服务不可用。",
      loading: "加载中...",
      added: "已添加",
      lastUsed: "最近使用",
      operationFailed: "无法完成通行密钥操作。",
      configurationRequired: "尚未配置通行密钥。",
      challengeExpired: "通行密钥请求已过期，请重试。",
      credentialLimit: "已达到通行密钥数量上限。",
      passkeyUnavailable: "没有可用的通行密钥。",
      verificationFailed: "通行密钥验证失败。",
      syncedCredentialsNotAllowed: "此通行密钥由提供方同步。请在插件安全策略中开启“允许同步通行密钥”后重试。",
      authenticationRequired: "登录会话已过期。",
    },
  };

  function currentLocale() {
    var value = localStorage.getItem("i18nextLng") || document.documentElement.lang || navigator.language || "en";
    return /^zh/i.test(value) ? "zh-CN" : "en";
  }

  function t(key) {
    return messages[currentLocale()][key] || messages.en[key] || key;
  }

  function supportsPasskeys() {
    return Boolean(window.PublicKeyCredential && navigator.credentials);
  }

  function api(path, options) {
    var request = Object.assign({ credentials: "same-origin" }, options || {});
    if (request.body) {
      request.headers = Object.assign({ "Content-Type": "application/json" }, request.headers || {});
    }
    var separator = path.indexOf("?") === -1 ? "?" : "&";
    return fetch(apiRoot + path + separator + "origin=" + encodeURIComponent(window.location.origin), request).then(function (response) {
      return response.json().then(function (body) {
        if (!response.ok || body.ok !== true) {
          var error = new Error(body.code || "request_failed");
          error.code = body.code;
          throw error;
        }
        return body;
      });
    });
  }

  function getStatus(force) {
    if (!force && state.status) {
      return Promise.resolve(state.status);
    }
    if (state.statusRequest) {
      return state.statusRequest;
    }
    state.statusRequest = api("/status", { method: "GET" }).then(
      function (status) {
        state.status = status;
        state.statusRequest = null;
        return status;
      },
      function (error) {
        state.statusRequest = null;
        throw error;
      },
    );
    return state.statusRequest;
  }

  function clearStatus() {
    state.status = null;
    state.statusRequest = null;
  }

  function errorMessage(error) {
    var code = error && error.code ? error.code : error && error.message;
    var keys = {
      configuration_required: "configurationRequired",
      challenge_expired: "challengeExpired",
      credential_limit_reached: "credentialLimit",
      passkey_unavailable: "passkeyUnavailable",
      verification_failed: "verificationFailed",
      synced_credential_not_allowed: "syncedCredentialsNotAllowed",
      authentication_required: "authenticationRequired",
      service_unavailable: "unavailable",
    };
    return keys[code] ? t(keys[code]) : t("operationFailed");
  }

  function arrayBufferFromBase64URL(value) {
    var base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    var padding = base64.length % 4;
    if (padding) {
      base64 += "=".repeat(4 - padding);
    }
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
  }

  function base64URLFromArrayBuffer(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var index = 0; index < bytes.length; index += 1) {
      binary += String.fromCharCode(bytes[index]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function creationOptions(options) {
    var result = Object.assign({}, options);
    result.challenge = arrayBufferFromBase64URL(options.challenge);
    result.user = Object.assign({}, options.user, {
      id: arrayBufferFromBase64URL(options.user.id),
    });
    if (options.excludeCredentials) {
      result.excludeCredentials = options.excludeCredentials.map(function (credential) {
        return Object.assign({}, credential, {
          id: arrayBufferFromBase64URL(credential.id),
        });
      });
    }
    return result;
  }

  function requestOptions(options) {
    var result = Object.assign({}, options);
    result.challenge = arrayBufferFromBase64URL(options.challenge);
    if (options.allowCredentials) {
      result.allowCredentials = options.allowCredentials.map(function (credential) {
        return Object.assign({}, credential, {
          id: arrayBufferFromBase64URL(credential.id),
        });
      });
    }
    return result;
  }

  function credentialJSON(credential) {
    var response = credential.response;
    var value = {
      id: credential.id,
      rawId: base64URLFromArrayBuffer(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      response: {
        clientDataJSON: base64URLFromArrayBuffer(response.clientDataJSON),
      },
    };
    if (credential.authenticatorAttachment) {
      value.authenticatorAttachment = credential.authenticatorAttachment;
    }
    if (response.attestationObject) {
      value.response.attestationObject = base64URLFromArrayBuffer(response.attestationObject);
      if (typeof response.getTransports === "function") {
        value.response.transports = response.getTransports();
      }
      return value;
    }
    value.response.authenticatorData = base64URLFromArrayBuffer(response.authenticatorData);
    value.response.signature = base64URLFromArrayBuffer(response.signature);
    if (response.userHandle) {
      value.response.userHandle = base64URLFromArrayBuffer(response.userHandle);
    }
    return value;
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
  }

  function radixButton(label, soft, color) {
    var button = element(
      "button",
      "rt-reset rt-BaseButton rt-r-size-2 " + (soft ? "rt-variant-soft" : "rt-variant-solid") + " rt-Button",
      label,
    );
    button.type = "button";
    button.setAttribute("data-accent-color", color);
    return button;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function loginError(dialog, message) {
    var current = dialog.querySelector(".km-passkey-error");
    if (!current) {
      current = element("div", "km-passkey-error");
      current.setAttribute("role", "alert");
      var form = dialog.querySelector(".km-login-form, .km-restricted-login-form");
      (form || dialog).appendChild(current);
    }
    current.textContent = message;
  }

  function loginWithPasskey(button, dialog) {
    button.disabled = true;
    button.textContent = t("loading");
    api("/authentication/options", {
      method: "POST",
      body: "{}",
    })
      .then(function (begin) {
        return navigator.credentials.get({
          publicKey: requestOptions(begin.options),
        }).then(function (credential) {
          if (!credential) {
            throw new Error("verification_failed");
          }
          return api("/authentication/verify", {
            method: "POST",
            body: JSON.stringify({
              challenge_id: begin.challenge_id,
              response: credentialJSON(credential),
            }),
          });
        });
      })
      .then(function () {
        if (!dialog.classList.contains("km-login-card")) {
          window.location.reload();
          return;
        }
        var redirect = "/admin/dashboard";
        try {
          redirect = new URLSearchParams(window.location.search).get("redirect") || redirect;
          if (
            redirect.charAt(0) !== "/" ||
            redirect.charAt(1) === "/" ||
            redirect.indexOf("\\") !== -1
          ) {
            redirect = "/admin/dashboard";
          }
          var target = new URL(redirect, window.location.origin);
          if (target.origin !== window.location.origin) {
            redirect = "/admin/dashboard";
          } else {
            redirect = target.pathname + target.search + target.hash;
          }
        } catch (error) {
          redirect = "/admin/dashboard";
        }
        window.location.replace(redirect);
      })
      .catch(function (error) {
        loginError(dialog, errorMessage(error));
        button.disabled = false;
        button.textContent = t("login");
      });
  }

  function mountLoginButtons() {
    if (!supportsPasskeys()) {
      return;
    }
    getStatus().then(function (status) {
      if (!status.enabled) {
        return;
      }
      document.querySelectorAll(".km-login-card, .km-login-dialog, .km-restricted-login-dialog").forEach(function (dialog) {
        if (dialog.querySelector(".km-passkey-login")) {
          return;
        }
        var form = dialog.querySelector(".km-login-form, .km-restricted-login-form");
        if (!form) {
          return;
        }
        var container = form.querySelector(".rt-Flex") || form;
        var button = radixButton(t("login"), true, "");
        button.classList.add("km-passkey-login", "w-full");
        button.addEventListener("click", function () {
          loginWithPasskey(button, dialog);
        });
        container.appendChild(button);
      });
    });
  }

  function dialogShell(title, copy) {
    var overlay = element("div", "rt-BaseDialogOverlay rt-DialogOverlay km-passkey-dialog-overlay");
    var scroll = element("div", "rt-BaseDialogScroll rt-DialogScroll");
    var padding = element("div", "rt-BaseDialogScrollPadding rt-DialogScrollPadding rt-r-align-center");
    var dialog = element("section", "rt-BaseDialogContent rt-DialogContent rt-r-size-3 km-passkey-dialog");
    overlay.setAttribute("data-state", "open");
    dialog.setAttribute("data-state", "open");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.tabIndex = -1;
    var heading = element("h2", "rt-Heading rt-r-size-5 rt-r-mb-3 km-passkey-dialog-title", title);
    dialog.appendChild(heading);
    if (copy) {
      dialog.appendChild(element("p", "rt-Text rt-r-size-3 km-passkey-dialog-copy", copy));
    }
    padding.appendChild(dialog);
    scroll.appendChild(padding);
    overlay.appendChild(scroll);

    function close() {
      document.removeEventListener("keydown", onKeydown);
      overlay.remove();
    }

    function onKeydown(event) {
      if (event.key === "Escape") {
        close();
      }
    }

    scroll.addEventListener("click", function (event) {
      if (event.target === scroll || event.target === padding) {
        close();
      }
    });
    document.addEventListener("keydown", onKeydown);
    document.querySelector(".radix-themes").appendChild(overlay);
    return {
      dialog: dialog,
      close: close,
    };
  }

  function renderCredentials(section, data) {
    clear(section);
    section.appendChild(element("label", "font-bold text-2xl", t("passkey")));
    var status = element("label", "km-passkey-account-status");
    section.appendChild(status);

    if (!data.service_available) {
      status.textContent = t("unavailable");
      return;
    }
    if (!data.configured) {
      status.textContent = t("notConfigured");
      return;
    }

    var credentials = data.credentials || [];
    status.textContent = credentials.length ? "" : t("noPasskeys");
    var list = element("div", "km-passkey-credentials");
    credentials.forEach(function (credential) {
      var item = element("div", "km-passkey-credential");
      var copy = element("div", "km-passkey-credential-copy");
      copy.appendChild(element("label", "font-bold km-passkey-credential-name", credential.name));
      var meta = t("added") + ": " + new Date(credential.created_at).toLocaleString();
      if (credential.last_used_at) {
        meta += " | " + t("lastUsed") + ": " + new Date(credential.last_used_at).toLocaleString();
      }
      copy.appendChild(element("label", "km-passkey-credential-meta", meta));
      item.appendChild(copy);
      var remove = radixButton(t("delete"), true, "red");
      remove.addEventListener("click", function () {
        deleteCredential(section, credential);
      });
      item.appendChild(remove);
      list.appendChild(item);
    });
    section.appendChild(list);

    if (supportsPasskeys()) {
      var actions = element("div", "km-passkey-account-actions");
      var add = radixButton(t("add"), false, "");
      add.addEventListener("click", function () {
        registerCredential(section);
      });
      actions.appendChild(add);
      section.appendChild(actions);
    }
  }

  function loadCredentials(section) {
    clear(section);
    section.appendChild(element("label", "font-bold text-2xl", t("passkey")));
    section.appendChild(element("label", "km-passkey-account-status", t("loading")));
    api("/credentials", { method: "GET" })
      .then(function (data) {
        renderCredentials(section, data);
      })
      .catch(function (error) {
        clear(section);
        section.appendChild(element("label", "font-bold text-2xl", t("passkey")));
        section.appendChild(element("label", "km-passkey-account-status", errorMessage(error)));
      });
  }

  function registerCredential(section) {
    var shell = dialogShell(t("addTitle"), "");
    var field = element("label", "km-passkey-dialog-field");
    field.appendChild(element("span", "", t("name")));
    var root = element("div", "rt-TextFieldRoot rt-r-size-2 rt-variant-surface");
    var input = element("input", "rt-reset rt-TextFieldInput");
    input.type = "text";
    input.value = t("defaultName");
    input.maxLength = 100;
    root.appendChild(input);
    field.appendChild(root);
    shell.dialog.appendChild(field);
    var actions = element("div", "km-passkey-dialog-actions");
    var cancel = radixButton(t("cancel"), true, "gray");
    var confirm = radixButton(t("register"), false, "");
    cancel.addEventListener("click", shell.close);
    confirm.addEventListener("click", function () {
      confirm.disabled = true;
      confirm.textContent = t("loading");
      api("/registration/options", {
        method: "POST",
        body: "{}",
      })
        .then(function (begin) {
          return navigator.credentials.create({
            publicKey: creationOptions(begin.options),
          }).then(function (credential) {
            if (!credential) {
              throw new Error("verification_failed");
            }
            return api("/registration/verify", {
              method: "POST",
              body: JSON.stringify({
                challenge_id: begin.challenge_id,
                name: input.value.trim() || t("defaultName"),
                response: credentialJSON(credential),
              }),
            });
          });
        })
        .then(function () {
          clearStatus();
          shell.close();
          loadCredentials(section);
        })
        .catch(function (error) {
          confirm.disabled = false;
          confirm.textContent = t("register");
          var note = shell.dialog.querySelector(".km-passkey-error");
          if (!note) {
            note = element("div", "km-passkey-error");
            note.setAttribute("role", "alert");
            shell.dialog.appendChild(note);
          }
          note.textContent = errorMessage(error);
        });
    });
    actions.appendChild(cancel);
    actions.appendChild(confirm);
    shell.dialog.appendChild(actions);
    setTimeout(function () {
      input.focus();
      input.select();
    }, 0);
  }

  function deleteCredential(section, credential) {
    var shell = dialogShell(t("deleteTitle"), t("deleteCopy"));
    var actions = element("div", "km-passkey-dialog-actions");
    var cancel = radixButton(t("cancel"), true, "gray");
    var confirm = radixButton(t("delete"), false, "red");
    cancel.addEventListener("click", shell.close);
    confirm.addEventListener("click", function () {
      confirm.disabled = true;
      api("/credentials/delete", {
        method: "POST",
        body: JSON.stringify({ credential_id: credential.id }),
      })
        .then(function () {
          clearStatus();
          shell.close();
          loadCredentials(section);
        })
        .catch(function (error) {
          confirm.disabled = false;
          var note = shell.dialog.querySelector(".km-passkey-error");
          if (!note) {
            note = element("div", "km-passkey-error");
            note.setAttribute("role", "alert");
            shell.dialog.appendChild(note);
          }
          note.textContent = errorMessage(error);
        });
    });
    actions.appendChild(cancel);
    actions.appendChild(confirm);
    shell.dialog.appendChild(actions);
  }

  function mountAccountPanels() {
    document.querySelectorAll(".km-page-admin-account").forEach(function (root) {
      if (root.querySelector(".km-passkey-account")) {
        return;
      }
      var section = element("section", "rt-Flex rt-r-fd-column rt-r-gap-2 km-passkey-account gap-2");
      root.appendChild(section);
      loadCredentials(section);
    });
  }

  function scan() {
    mountLoginButtons();
    mountAccountPanels();
  }

  var observer = new MutationObserver(scan);
  observer.observe(document.documentElement, { childList: true, subtree: true });
  scan();
})();
