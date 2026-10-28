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

// A job's page streams its output. Lines are added as text nodes, never as
// HTML; when the job changes state the page reloads to show the question,
// the result and the right buttons.
(function () {
  "use strict";
  var log = document.getElementById("job-log");
  var box = document.getElementById("job-state");
  if (!log || !box || !window.EventSource) {
    return;
  }
  var state = box.getAttribute("data-state");
  if (state !== "running" && state !== "waiting") {
    return;
  }
  var seen = log.textContent.split("\n").length - 1;
  var count = 0;
  var events = new EventSource(log.getAttribute("data-events"));
  events.addEventListener("line", function (e) {
    count += 1;
    if (count <= seen) {
      return; // already on the page
    }
    log.appendChild(document.createTextNode(e.data + "\n"));
  });
  events.addEventListener("state", function (e) {
    if (e.data !== state) {
      events.close();
      window.location.reload();
    }
  });
})();
