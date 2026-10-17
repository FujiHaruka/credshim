(() => {
  const match = location.pathname.match(/^(.*\/)(en|ja)(\/.*)$/);
  if (!match) return;
  const [, base, lang, page] = match;
  const other = lang === "en" ? "ja" : "en";
  const link = document.createElement("a");
  link.href = base + other + page;
  link.lang = other;
  link.hreflang = other;
  link.className = "lang-switch";
  link.textContent = other === "ja" ? "日本語" : "English";
  document.querySelector(".right-buttons")?.prepend(link);
})();
