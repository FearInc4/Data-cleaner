// Tiny progressive enhancements. Everything works without JS.
(function () {
  // Copy-to-clipboard buttons: <button class="copy" data-copy="text">
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (!btn) return;
    e.preventDefault();
    var text = btn.getAttribute("data-copy");
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function () {
        var old = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = old; }, 1200);
      });
    }
  });

  // Confirm dangerous actions: <form data-confirm="Are you sure?">
  document.addEventListener("submit", function (e) {
    var msg = e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // Select-all checkboxes: <input type="checkbox" data-select-all="name">
  document.addEventListener("change", function (e) {
    var name = e.target.getAttribute && e.target.getAttribute("data-select-all");
    if (!name) return;
    document.querySelectorAll('input[type=checkbox][name="' + name + '"]').forEach(function (cb) {
      if (!cb.disabled) cb.checked = e.target.checked;
    });
  });

  // Quick-select buttons: <button data-select="broker_id" data-filter="p1">
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-select]");
    if (!btn) return;
    e.preventDefault();
    var name = btn.getAttribute("data-select");
    var filter = btn.getAttribute("data-filter");
    document.querySelectorAll('input[type=checkbox][name="' + name + '"]').forEach(function (cb) {
      if (cb.disabled) return;
      cb.checked = filter === "none" ? false : filter === "all" ? true : cb.classList.contains(filter);
    });
  });

  // Auto-refresh while a background scan runs: <body data-refresh="5">
  var refresh = document.body.getAttribute("data-refresh");
  if (refresh) setTimeout(function () { window.location.reload(); }, parseInt(refresh, 10) * 1000);

  // Region dropdown follows the country picker on the profile form.
  var country = document.getElementById("country");
  var regionWrap = document.querySelectorAll("[data-region-for]");
  function syncRegions() {
    if (!country) return;
    regionWrap.forEach(function (el) {
      var match = el.getAttribute("data-region-for") === country.value;
      el.hidden = !match;
      var sel = el.querySelector("select");
      if (sel) sel.disabled = !match;
    });
    var other = document.getElementById("region-other");
    if (other) {
      var any = Array.prototype.some.call(regionWrap, function (el) { return el.getAttribute("data-region-for") === country.value; });
      other.hidden = any;
      other.querySelector("input").disabled = any;
    }
  }
  if (country) { country.addEventListener("change", syncRegions); syncRegions(); }
})();
