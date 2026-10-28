// sshmgr web UI: the whole of its own JavaScript. Every page works without it;
// this only adds conveniences on top, and never builds HTML from strings.
(function () {
  "use strict";

  // The history filter's source list applies as soon as it changes.
  var source = document.getElementById("f-source");
  if (source && source.form) {
    source.addEventListener("change", function () { source.form.submit(); });
  }
})();
