(() => {
  let failed = false;
  let ready = false;
  let handlersReady = false;
  const markReady = () => { ready = true; };
  const showFailure = () => {
    if (failed || ready) return;
    failed = true;
    const content = document.querySelector("#content");
    if (content) {
      content.innerHTML = '<div class="state-card state-error" role="alert"><span class="state-icon" aria-hidden="true">⚠️</span><h3>تعذّر تشغيل الموقع</h3><p>أعد تحميل الصفحة. إذا استمرت المشكلة، أرسل الخطأ الظاهر في Console إلى مدير الموقع.</p><button class="cta" type="button" id="boot-retry">إعادة المحاولة</button></div>';
      document.querySelector("#boot-retry")?.addEventListener("click", () => location.reload());
    }
  };
  window.addEventListener("masaha:ready", markReady, { once: true });
  window.addEventListener("masaha:handlers-ready", () => { handlersReady = true; }, { once: true });
  window.addEventListener("error", event => {
    if (event.target?.tagName === "SCRIPT" || event.filename?.includes("app.js")) showFailure();
  }, true);
  window.addEventListener("unhandledrejection", showFailure);
  document.addEventListener("submit", async event => {
    const form = event.target;
    if (handlersReady || form.id !== "auth-form") return;
    event.preventDefault();
    const error = document.querySelector("#auth-error");
    if (error) error.textContent = "جارٍ التحقق من بيانات الدخول…";
    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(Object.fromEntries(new FormData(form)))
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "تعذّر تسجيل الدخول.");
      location.reload();
    } catch (errorResult) {
      if (error) error.textContent = errorResult.message || "تعذّر الاتصال بالخادم.";
    }
  });
  setTimeout(() => {
    if (!ready && document.querySelector("#content .loading-state")) showFailure();
  }, 30000);
  document.addEventListener("click", event => {
    if (handlersReady || ready || !event.target.closest("#login-open, #join-button")) return;
    event.preventDefault();
    const dialog = document.querySelector("#auth-dialog");
    if (dialog && !dialog.open) dialog.showModal();
  }, true);
})();
