(() => {
  let failed = false;
  let ready = false;
  let handlersReady = false;
  let fallbackMode = "login";
  const markReady = () => { ready = true; };
  const showFailure = detail => {
    if (failed || ready) return;
    failed = true;
    const content = document.querySelector("#content");
    if (content) {
      content.innerHTML = '<div class="state-card state-error" role="alert"><span class="state-icon" aria-hidden="true">⚠️</span><h3>تعذّر تشغيل الموقع</h3><p>أعد تحميل الصفحة. إذا استمرت المشكلة، أرسل سبب العطل إلى مدير الموقع.</p><p id="boot-error-detail" class="muted"></p><button class="cta" type="button" id="boot-retry">إعادة المحاولة</button></div>';
      const detailText = typeof detail === "string" ? detail : detail?.message || detail?.reason?.message || "انتهت مهلة تشغيل الواجهة.";
      document.querySelector("#boot-error-detail").textContent = detailText;
      document.querySelector("#boot-retry")?.addEventListener("click", () => location.reload());
    }
  };
  window.addEventListener("masaha:ready", markReady, { once: true });
  window.addEventListener("masaha:handlers-ready", () => { handlersReady = true; }, { once: true });
  window.addEventListener("error", event => {
    if (event.target?.tagName === "SCRIPT" || event.filename?.includes("app.js")) showFailure(event.message || event.error);
  }, true);
  window.addEventListener("unhandledrejection", event => showFailure(event.reason));
  document.addEventListener("submit", async event => {
    const form = event.target;
    if (handlersReady || form.id !== "auth-form") return;
    event.preventDefault();
    const error = document.querySelector("#auth-error");
    if (error) error.textContent = fallbackMode === "register" ? "جارٍ إنشاء الحساب…" : "جارٍ التحقق من بيانات الدخول…";
    try {
      const response = await fetch(`/api/${fallbackMode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(Object.fromEntries(new FormData(form)))
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || (fallbackMode === "register" ? "تعذّر إنشاء الحساب." : "تعذّر تسجيل الدخول."));
      location.reload();
    } catch (errorResult) {
      if (error) error.textContent = errorResult.message || "تعذّر الاتصال بالخادم.";
    }
  });
  setTimeout(() => {
    if (!ready && document.querySelector("#content .loading-state")) showFailure();
  }, 30000);
  const switchFallbackMode = mode => {
    fallbackMode = mode;
    const registering = mode === "register";
    document.querySelector("#name-field").hidden = !registering;
    document.querySelector("#username-field").hidden = !registering;
    document.querySelector("#auth-name").required = registering;
    document.querySelector("#auth-username").required = registering;
    const email = document.querySelector('#auth-form [name="email"]');
    email.type = registering ? "email" : "text";
    email.autocomplete = registering ? "email" : "username";
    document.querySelector("#auth-email-label").textContent = registering ? "البريد الإلكتروني" : "البريد الإلكتروني أو اسم المستخدم";
    document.querySelector("#auth-title").textContent = registering ? "إنشاء حساب" : "تسجيل الدخول";
    document.querySelector("#auth-submit").textContent = registering ? "إنشاء حساب" : "دخول";
    document.querySelector("#forgot-open").hidden = registering;
    document.querySelector("#login-tab").classList.toggle("active", !registering);
    document.querySelector("#register-tab").classList.toggle("active", registering);
  };
  document.addEventListener("click", event => {
    if (handlersReady || ready) return;
    const target = event.target;
    if (target.closest("#login-tab")) { switchFallbackMode("login"); return; }
    if (target.closest("#register-tab")) { switchFallbackMode("register"); return; }
    const trigger = target.closest("#login-open, #join-button");
    if (!trigger) return;
    event.preventDefault();
    switchFallbackMode(trigger.id === "join-button" ? "register" : "login");
    const dialog = document.querySelector("#auth-dialog");
    if (dialog && !dialog.open) dialog.showModal();
  }, true);
})();
